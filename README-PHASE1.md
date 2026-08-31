# KH Code 2FA — Source Modification Phase 1

Modified real application source files:

## frontend/src/main.tsx
- Added persistent Dark/Light theme preference using localStorage.
- Added authenticator search input and filters account cards by name.
- Added inline rename action for authenticator display names.
- Removed the 2FA Recovery Codes state, generation function, settings UI, and modal UI.
- Moved Change Vault Lock access to Settings.
- Removed Change Vault Lock and Lock Vault Now actions from the profile menu.
- Removed the header Add action and added a floating Add button above the mobile dock.
- Preserved existing camera/image QR flow and vault logic.

## Verification status
- Source was modified directly in the active frontend entry point.
- Dependency installation/build verification was attempted but npm installation timed out in this execution environment, so a successful production build is NOT claimed.
- OAuth multi-account, encrypted transfer format, and account-specific Inbox still require backend/API work and are not claimed complete in this phase.
