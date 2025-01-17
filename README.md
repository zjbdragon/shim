THIS IS A FORK OF RED HAT SHIM. YOU SHOULD VISIT THE ORIGINAL AT
[https://github.com/rhboot/shim](https://github.com/rhboot/shim)

I plan to do some TPM-related experiments here. Intel TXT's TPM policies
don't work with UEFI Secure Boot. Maybe Shim can replace TXT.

---------------------------------------------------------------------

shim is a trivial EFI application that, when run, attempts to open and
execute another application. It will initially attempt to do this via the
standard EFI LoadImage() and StartImage() calls. If these fail (because secure
boot is enabled and the binary is not signed with an appropriate key, for
instance) it will then validate the binary against a built-in certificate. If
this succeeds and if the binary or signing key are not blacklisted then shim
will relocate and execute the binary.

shim will also install a protocol which permits the second-stage bootloader
to perform similar binary validation. This protocol has a GUID as described
in the shim.h header file and provides a single entry point. On 64-bit systems
this entry point expects to be called with SysV ABI rather than MSABI, so calls
to it should not be wrapped.

On systems with a TPM chip enabled and supported by the system firmware,
shim will extend various PCRs with the digests of the targets it is
loading.  A full list is in the file README.tpm .

To use shim, simply place a DER-encoded public certificate in a file such as
pub.cer and build with "make VENDOR_CERT_FILE=pub.cer".

There are a couple of build options, and a couple of ways to customize the
build, described in BUILDING.
