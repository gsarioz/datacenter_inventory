const datacenterSelect = document.querySelector("#datacenter-select");
const rackSelect = document.querySelector("#rack-select");

if (datacenterSelect && rackSelect) {
  datacenterSelect.addEventListener("change", async () => {
    const datacenterId = datacenterSelect.value;
    rackSelect.innerHTML = '<option value="">Select rack</option>';
    if (!datacenterId) {
      return;
    }

    const response = await fetch(`/api/datacenters/${datacenterId}/racks`);
    const data = await response.json();
    for (const rack of data.racks) {
      const option = document.createElement("option");
      option.value = rack.id;
      option.textContent = rack.name;
      rackSelect.appendChild(option);
    }
  });
}
