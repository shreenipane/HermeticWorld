The deterministic gzip JSON fixture contains the five unmodified upstream
Firecracker v1.18.0 files touched by the host filter patch. It was extracted from
source archive SHA256
89f02fe6867edcf0a0154305d5533a611e48eaa99ba11d24aa2f076492bef615
(commit eaf83bb718a559d324613d566eaf776b31a62340).
Upstream copyright and Apache-2.0 notices are retained in each source file.
The regression applies the shipping patch offline, checks the complete seccomp
policy and verifies that boot/restore wiring has no duplicate declarations.
