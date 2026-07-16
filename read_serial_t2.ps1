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
'@

$selFido = [byte[]](0x00,0xA4,0x04,0x00,0x08, 0xA0,0x00,0x00,0x06,0x47,0x2F,0x00,0x01)
$getInfo = [byte[]](0x80,0x33,0x00,0x00,0x12, 0xD1,0x10) + (New-Object byte[] 16)

$ctx = [IntPtr]::Zero
if ([SC]::SCardEstablishContext(2,[IntPtr]::Zero,[IntPtr]::Zero,[ref]$ctx) -ne 0) { exit 1 }
try {
    $len = 0; [void][SC]::SCardListReaders($ctx,$null,$null,[ref]$len)
    if ($len -le 0) { exit 1 }
    $buf = New-Object char[] $len
    [void][SC]::SCardListReaders($ctx,$null,$buf,[ref]$len)
    $readers = (-join $buf).Split([char]0) | Where-Object { $_ }
    $targets = @($readers | Where-Object { $_ -match 'Token2|FIDO|CCID' })
    if (-not $targets) { $targets = $readers }

    foreach ($r in $targets) {
        $card = [IntPtr]::Zero; $proto = 0
        if ([SC]::SCardConnect($ctx,$r,2,3,[ref]$card,[ref]$proto) -ne 0) { continue }
        try {
            $io = New-Object SC+IO; $io.Protocol = $proto; $io.PciLength = 8
            $rsp = New-Object byte[] 512

            $rl = $rsp.Length
            [void][SC]::SCardTransmit($card,[ref]$io,$selFido,$selFido.Length,[IntPtr]::Zero,$rsp,[ref]$rl)

            $rl = $rsp.Length
            if ([SC]::SCardTransmit($card,[ref]$io,$getInfo,$getInfo.Length,[IntPtr]::Zero,$rsp,[ref]$rl) -ne 0) { continue }
            if ($rl -lt 4) { continue }
            if ($rsp[$rl-2] -ne 0x90 -or $rsp[$rl-1] -ne 0x00) { continue }
            if ($rsp[0] -ne 0xD1) { continue }

            $snLen = $rsp[1]
            $ascii = [Text.Encoding]::ASCII.GetString($rsp[2..(1+$snLen)])
            $bytes = for ($i=0; $i -lt $ascii.Length; $i+=2) { [Convert]::ToByte($ascii.Substring($i,2),16) }
            (($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join '')
            exit 0
        } finally { [void][SC]::SCardDisconnect($card,0) }
    }
    exit 1
} finally { [void][SC]::SCardReleaseContext($ctx) }
