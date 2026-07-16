#Requires -Version 5.1
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SC {
    [DllImport("winscard.dll")] public static extern int SCardEstablishContext(int scope, IntPtr r1, IntPtr r2, out IntPtr ctx);
    [DllImport("winscard.dll")] public static extern int SCardReleaseContext(IntPtr ctx);
    [DllImport("winscard.dll", CharSet=CharSet.Unicode)] public static extern int SCardListReaders(IntPtr ctx, string groups, char[] readers, ref int len);
    [DllImport("winscard.dll", CharSet=CharSet.Unicode)] public static extern int SCardConnect(IntPtr ctx, string reader, int share, int prefProto, out IntPtr card, out int activeProto);
    [DllImport("winscard.dll")] public static extern int SCardDisconnect(IntPtr card, int disp);
    [DllImport("winscard.dll")] public static extern int SCardTransmit(IntPtr card, ref IO pio, byte[] send, int sendLen, IntPtr pioRecv, byte[] recv, ref int recvLen);
    [StructLayout(LayoutKind.Sequential)] public struct IO { public int Protocol; public int PciLength; }
}
'@ -ErrorAction SilentlyContinue

# SELECT FIDO applet: 00 A4 04 00 08 A0 00 00 06 47 2F 00 01
$selFido = [byte[]](0x00,0xA4,0x04,0x00,0x08, 0xA0,0x00,0x00,0x06,0x47,0x2F,0x00,0x01)
# GET_INFO (spec 6.10): 80 33 00 00 12 D1 10 <16 zero bytes>
$getInfo = [byte[]](0x80,0x33,0x00,0x00,0x12, 0xD1,0x10) + (New-Object byte[] 16)

$ctx = [IntPtr]::Zero
if ([SC]::SCardEstablishContext(2,[IntPtr]::Zero,[IntPtr]::Zero,[ref]$ctx) -ne 0) { exit 1 }

try {
    $len = 0
    [void][SC]::SCardListReaders($ctx,$null,$null,[ref]$len)
    if ($len -le 0) { exit 1 }
    $buf = New-Object char[] $len
    [void][SC]::SCardListReaders($ctx,$null,$buf,[ref]$len)
    $readers = (-join $buf).Split([char]0) | Where-Object { $_ }

    $targets = @($readers | Where-Object { $_ -match 'Token2|TOKEN2|FIDO|CCID' })
    if (-not $targets) { $targets = $readers }

    foreach ($r in $targets) {
        $card = [IntPtr]::Zero; $proto = 0
        # Shared first, then Exclusive (mirrors keyroost's transport).
        $rc = [SC]::SCardConnect($ctx,$r,2,3,[ref]$card,[ref]$proto)
        if ($rc -ne 0) { $rc = [SC]::SCardConnect($ctx,$r,1,3,[ref]$card,[ref]$proto) }
        if ($rc -ne 0) { continue }

        try {
            $io = New-Object SC+IO; $io.Protocol = $proto; $io.PciLength = 8
            $rsp = New-Object byte[] 512

            # Fire the SELECT and ignore its status word: some PIN+ firmware
            # answers 6A81 yet still switches applets and serves the serial.
            $rl = $rsp.Length
            [void][SC]::SCardTransmit($card,[ref]$io,$selFido,$selFido.Length,[IntPtr]::Zero,$rsp,[ref]$rl)

            # GET_INFO
            $rl = $rsp.Length
            if ([SC]::SCardTransmit($card,[ref]$io,$getInfo,$getInfo.Length,[IntPtr]::Zero,$rsp,[ref]$rl) -ne 0) { continue }
            if ($rl -lt 2) { continue }

            $data = @()
            if ($rl -gt 2) { $data = $rsp[0..($rl-3)] }
            $sw1 = $rsp[$rl-2]; $sw2 = $rsp[$rl-1]

            # T=0 continuation: 61 xx means xx more bytes are waiting.
            $guard = 0
            while ($sw1 -eq 0x61) {
                $get = [byte[]](0x00,0xC0,0x00,0x00,$sw2)
                $rl = $rsp.Length
                if ([SC]::SCardTransmit($card,[ref]$io,$get,$get.Length,[IntPtr]::Zero,$rsp,[ref]$rl) -ne 0) { break }
                if ($rl -lt 2) { break }
                if ($rl -gt 2) { $data += $rsp[0..($rl-3)] }
                $sw1 = $rsp[$rl-2]; $sw2 = $rsp[$rl-1]
                if (++$guard -gt 64) { break }
            }

            if ($sw1 -ne 0x90 -or $sw2 -ne 0x00) { continue }
            if ($data.Count -lt 2 -or $data[0] -ne 0xD1) { continue }

            # Body: D1 <len> <ascii-hex...> — the SN is double-encoded.
            $snLen = $data[1]
            if ($data.Count -lt 2 + $snLen) { continue }
            $ascii = [Text.Encoding]::ASCII.GetString($data[2..(1+$snLen)])
            if ($ascii.Length % 2 -ne 0) { continue }
            $bytes = for ($i=0; $i -lt $ascii.Length; $i+=2) { [Convert]::ToByte($ascii.Substring($i,2),16) }

            (($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join '')
            exit 0
        }
        finally { [void][SC]::SCardDisconnect($card,0) }
    }
    exit 1
}
finally { [void][SC]::SCardReleaseContext($ctx) }
