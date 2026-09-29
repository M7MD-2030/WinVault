# Windows Dev VM for WinVault (Arch + KVM/libvirt)

This guide builds a dedicated VM, `winvault-dev`, for developing and testing WinVault. It follows the lab conventions: `$ISO`, `$DISK` and `$VIRTIO` under `/var/lib/libvirt/VMs`, `qemu:///system`, and golden base + overlay resets.

## Which Windows image?

Use an **official, unmodified Microsoft ISO**:

- **Windows 11** (recommended): download it from microsoft.com/software-download/windows11. During setup, choose **"I don't have a product key"** and install Pro. It installs and runs **without a time limit**. Unactivated Windows only shows a watermark and locks personalisation, which doesn't matter in a lab VM.
- **Properly licensed alternative:** as a university student, check whether your university offers **Azure Dev Tools for Teaching** (Microsoft's education program), which includes Windows licences for free.
- **Skip the "Enterprise Evaluation" ISO.** It's the one that expires after 90 days.
- **Don't use stripped third-party builds such as Tiny11.** A forensic baseline has to come from a known-clean, stock system. Those builds also remove services, tasks and Defender components, which are exactly what WinVault analyses, so your results would not reflect real machines.

> **RAM tip:** 16 GB total means ~6 GB for this VM is comfortable. Shut down other lab VMs while you develop.

## 1. Host packages

Install these once:

```bash
sudo pacman -S --needed qemu-desktop libvirt virt-install virt-viewer edk2-ovmf swtpm dnsmasq
sudo systemctl enable --now libvirtd
```

Windows 11 needs UEFI + Secure Boot (`edk2-ovmf`) and TPM 2.0 (`swtpm`).

## 2. Create the disk and VM

```bash
export VM=winvault-dev
sudo qemu-img create -f qcow2 $DISK/$VM-base.qcow2 64G

sudo virt-install \
  --connect qemu:///system \
  --name $VM \
  --osinfo win11 \
  --memory 6144 --vcpus 4 --cpu host-passthrough \
  --boot uefi \
  --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb \
  --disk path=$DISK/$VM-base.qcow2,bus=virtio,cache=none,discard=unmap \
  --cdrom $ISO/Win11_25H2_English_x64_v2.iso \
  --disk path=$VIRTIO,device=cdrom \
  --network network=default,model=virtio \
  --graphics spice --video qxl \
  --noautoconsole

virt-viewer --connect qemu:///system $VM &
```

- Use your exact ISO filename (`ls $ISO`). Microsoft sometimes adds suffixes like `_v2`, and zsh cancels the whole command if a wildcard matches nothing. `$VIRTIO` points at the `virtio-win.iso` file itself, not at a folder.
- The VM goes on **`default` (NAT)**, not `lab-isolated`. It needs internet to install Python, git and pip packages. It's a dev/test box, not a malware target.
- **No disk visible in Setup?** Click *Load driver* → browse the virtio CD → `viostor\w11\amd64`.
- **No network during OOBE?** That's expected until the virtio NIC driver is installed. At "Let's connect you to a network", press **Shift+F10** and run `start ms-cxh:localonly` to create a local account.

## 3. Inside Windows

1. Run `virtio-win-guest-tools.exe` from the virtio CD to install the network, balloon and QXL drivers, plus the SPICE agent for clipboard and resizing.
2. Open **Terminal (Admin)** and install the tools:
   ```powershell
   winget install -e --id Python.Python.3.12
   winget install -e --id Git.Git
   winget install -e --id Microsoft.VisualStudioCode   # optional
   ```
3. **Close Terminal and open a new Terminal (Admin).** Windows only picks up newly installed programs in new windows, so `git` and `py` won't be found in the old one. Then clone and install WinVault:
   ```powershell
   git clone https://github.com/M7MD-2030/WinVault.git C:\dev\WinVault
   cd C:\dev\WinVault
   py -m venv .venv; .\.venv\Scripts\Activate.ps1
   pip install -e ".[dev]"
   pytest -q
   winvault baseline --label "fresh install"
   ```
4. Let Windows Update finish and reboot a couple of times. This matters because the noise-filter work in Phase 2 needs a settled system to learn what "normal" looks like.

## 4. Freeze a clean base and reset from it

Use the same pattern as `labreset`. Shut the VM down, then put an overlay on top of the base:

```bash
sudo virsh shutdown winvault-dev
sudo chmod 444 $DISK/winvault-dev-base.qcow2       # base is now read-only
sudo qemu-img create -f qcow2 -F qcow2 -b $DISK/winvault-dev-base.qcow2 $DISK/winvault-dev.qcow2
sudo virt-xml winvault-dev --edit target=vda --disk path=$DISK/winvault-dev.qcow2
```

Add a reset helper to `~/.zshrc`. It throws away all changes since the base:

```zsh
wvreset() {
  sudo virsh destroy winvault-dev 2>/dev/null
  sudo rm -f $DISK/winvault-dev.qcow2
  sudo qemu-img create -q -f qcow2 -F qcow2 -b $DISK/winvault-dev-base.qcow2 $DISK/winvault-dev.qcow2
  echo "winvault-dev reset to clean base"
}
```

> Internal `virsh snapshot-create-as` snapshots don't work on UEFI (pflash) VMs, so the overlay approach is the reliable one.
>
> Keep your code on GitHub, not only inside the VM. `wvreset` wipes the overlay, including anything you haven't pushed.

## 5. Test loop

```powershell
winvault baseline --label clean
.\scripts\Test-WinVaultChanges.ps1        # harmless labelled changes
winvault compare --json report.json
.\scripts\Test-WinVaultChanges.ps1 -Cleanup
```

## Optional: move snapshots to the host

Snapshots are plain JSON, so you can diff them on Arch too:

```bash
pip install -e .              # inside your repo on the host
winvault diff baseline.json current.json
```
