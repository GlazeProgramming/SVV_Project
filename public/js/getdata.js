const form = document.getElementById("getdataForm");
const div = document.getElementById("showdata");

form.addEventListener("submit", async function (e) {
    e.preventDefault();

    try {
        const response = await fetch("/getdata");

        if (!response.ok) {
            throw new Error("HTTP error " + response.status);
        }

        const data = await response.json();
        console.log("DATA DARI /getdata:", data);

        if (!Array.isArray(data) || data.length === 0) {
            div.innerHTML = "<p>Tidak ada data.</p>";
            return;
        }

        // create table
        let html = `
            <table border="1" cellpadding="8" cellspacing="0">
                <thead>
                    <tr>
                        <th>First Name</th>
                        <th>Last Name</th>
                        <th>DOB</th>
                        <th>Phone Number</th>
                        <th>Username</th>
                        <th>Email</th>
                    </tr>
                </thead>
                <tbody>
        `;

        data.forEach((row) => {
            html += `
                <tr>
                    <td>${row.firstname ?? ""}</td>
                    <td>${row.lastname ?? ""}</td>
                    <td>${String(row.dob).split("T")[0]}</td>
                    <td>${row.phonenumber ?? ""}</td>
                    <td>${row.username ?? ""}</td>
                    <td>${row.email ?? ""}</td>
                </tr>
            `;
        });

        html += `
                </tbody>
            </table>
        `;

        div.innerHTML = html;

    } catch (error) {
        console.error("Fetch Error:", error);
        div.innerHTML = "<p style='color:red;'>Terjadi kesalahan saat mengambil data.</p>";
    }
});