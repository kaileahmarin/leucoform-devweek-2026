# DevWeek submission privacy boundary

The tracked repository and packaged application must not contain personal identifiers, raw chats,
absolute user-profile paths, private repository names, source patches from external projects,
credentials, provider transcripts, vault contents, or managed worktrees.

Build and test output is disposable. Release review scans tracked files and package contents for
credential-shaped strings, user-profile paths, local task metadata, and excluded historical naming.
Sanitized architecture and decision summaries replace raw conversational provenance.

NoTUG runtime receipts remain minimized and local. Prompt bytes are bounded, delivered through stdin,
and not stored by Leucoform by default. Provider processing after transfer remains outside NoTUG's
privacy control and must be acknowledged by the user.
