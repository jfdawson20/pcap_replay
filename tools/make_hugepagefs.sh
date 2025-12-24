#!/bin/bash
# setup_1g_hugepages.sh
# Usage: sudo ./setup_1g_hugepages.sh <num_pages>

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

if [ $# -ne 1 ]; then
  echo "Usage: $0 <num_1G_hugepages>"
  exit 1
fi

NUM_PAGES=$1
HUGEPAGE_PATH="/sys/kernel/mm/hugepages/hugepages-1048576kB"

if [ ! -d "$HUGEPAGE_PATH" ]; then
  echo "1G hugepages not supported on this system (missing $HUGEPAGE_PATH)"
  exit 1
fi

echo "Setting ${NUM_PAGES}x 1GB hugepages..."
echo $NUM_PAGES > ${HUGEPAGE_PATH}/nr_hugepages

echo "Verifying..."
cat ${HUGEPAGE_PATH}/nr_hugepages

# Mount the hugetlbfs if not already mounted
if ! mount | grep -q "/mnt/huge"; then
  mkdir -p /mnt/huge
  mount -t hugetlbfs nodev /mnt/huge -o pagesize=1G
  echo "Mounted 1G hugepages at /mnt/huge"
else
  echo "/mnt/huge already mounted"
fi

echo "Done."
