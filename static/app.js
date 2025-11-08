// static/app.js
console.log("✅ app.js loaded successfully");

async function register() {
  const name = document.getElementById('reg_name').value;
  const email = document.getElementById('reg_email').value;
  const password = document.getElementById('reg_password').value;
  const res = await fetch('/api/register', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({name, email, password}),
    credentials: 'same-origin'
  });
  const j = await res.json();
  if (res.ok) alert("Registered. You can log in now.");
  else alert("Error: " + (j.error || j.detail || JSON.stringify(j)));
}

async function login() {
  const email = document.getElementById('login_email').value;
  const password = document.getElementById('login_password').value;
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({email, password}),
    credentials: 'same-origin'
  });
  const j = await res.json();
  if (res.ok && j.status === 'ok') {
    if (j.role === 'admin') window.location = '/static/admin_dashboard.html';
    else window.location = '/static/dashboard.html';
  } else {
    alert("Login failed: " + (j.error || JSON.stringify(j)));
  }
}

async function adminLogin() {
  const email = document.getElementById('admin_email').value;
  const password = document.getElementById('admin_password').value;
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({email, password}),
    credentials: 'same-origin'
  });
  const j = await res.json();
  if (res.ok && j.status === 'ok') {
    if (j.role === 'admin') window.location = '/static/admin_dashboard.html';
    else alert("This account is not an admin.");
  } else {
    alert("Login failed: " + (j.error || JSON.stringify(j)));
  }
}

async function logout() {
  document.cookie = "BANKSESSION=;path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT";
  window.location = '/static/index.html';
}

// user functions
async function createAccount() {
  const t = document.getElementById('acct_type').value;

  try {
    const res = await fetch('/api/create_account', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({account_type: t}),
      credentials: 'same-origin'
    });

    const j = await res.json();
    console.log("📦 create_account response:", j);

    if (res.ok && j.account_number) {
      alert(`✅ Account created!\nNumber: ${j.account_number}\nType: ${t}`);
      loadAccounts();  // refresh list once
    } else {
      alert("Error: " + (j.error || j.message || JSON.stringify(j)));
    }
  } catch (err) {
    console.error("❌ createAccount failed:", err);
    alert("Network error. Try again.");
  }
}

async function loadAccounts() {
  console.log("🔍 loadAccounts() triggered");

  const el = document.getElementById('accounts_list');
  if (!el) {
    console.warn("⚠️ No #accounts_list element found in DOM");
    return;
  }

  el.innerHTML = "<div style='color:#555;'>Loading accounts...</div>";

  try {
    const res = await fetch('/api/accounts', { 
      method: 'POST', 
      credentials: 'same-origin'
    });

    const j = await res.json();
    console.log("📦 Accounts response:", j);

    if (!res.ok || !j.accounts) {
      el.innerHTML = `<div style="color:red;">Error: ${j.error || 'Failed to load accounts'}</div>`;
      return;
    }

    const rows = j.accounts;
    if (rows.length === 0) {
      el.innerHTML = "<div>No accounts yet.</div>";
      return;
    }

    // ✅ Render all accounts neatly
    el.innerHTML = rows.map(r => `
      <div class="account-card" 
           style="
             border:1px solid #ddd;
             background:#fff;
             border-radius:8px;
             margin:8px 0;
             padding:10px;
             box-shadow:0 1px 3px rgba(0,0,0,0.08);
           ">
        <strong>${r.account_number}</strong> 
        <span style="color:#555;">(${r.account_type})</span>
        <div>Balance: ₹${parseFloat(r.balance).toFixed(2)}</div>
      </div>
    `).join('');
  } catch (e) {
    console.error("❌ Error fetching accounts:", e);
    el.innerHTML = "<div style='color:red;'>Network or fetch error</div>";
  }
}



async function makeTx() {
  const account_number = document.getElementById('src_account').value;
  const transaction_type = document.getElementById('tx_type').value;
  const amount = document.getElementById('amount').value;
  const to_account_number = document.getElementById('to_account').value;
  const body = { account_number, transaction_type, amount };
  if (transaction_type === 'transfer') body.to_account_number = to_account_number;
  const res = await fetch('/api/transaction', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(body),
    credentials: 'same-origin'
  });
  const j = await res.json();
  if (res.ok) { alert("Success: " + j.transaction_id); loadAccounts(); }
  else alert("Error: " + (j.error || j.detail || JSON.stringify(j)));
}

// transactions page load
document.addEventListener("DOMContentLoaded", () => {
  const loadBtn = document.getElementById("loadTransactions");
  if (loadBtn) {
    loadBtn.addEventListener("click", async () => {
      const accountNumber = document.getElementById("accountNumber").value.trim();
      if (!accountNumber) { alert("Please enter an account number!"); return; }
      try {
        const res = await fetch(`/api/transactions/${accountNumber}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: 'same-origin'
        });
        const data = await res.json();
        const tbody = document.querySelector("#transactionsTable tbody");
        tbody.innerHTML = "";
        if (!res.ok) { alert(data.error || "Error fetching transactions"); return; }
        (data.transactions || []).forEach(tx => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${tx.transaction_id}</td>
            <td>${tx.transaction_type}</td>
            <td>${tx.amount}</td>
            <td>${tx.to_account_number || "-"}</td>
            <td>${tx.transaction_log}</td>
            <td>${new Date(tx.created_at).toLocaleString()}</td>
          `;
          tbody.appendChild(tr);
        });
        if ((data.transactions || []).length === 0) tbody.innerHTML = "<tr><td colspan='6'>No transactions found.</td></tr>";
      } catch (err) {
        console.error(err);
        alert("Error loading transactions.");
      }
    });
  }

  // admin page bindings
  const adminLoadBtn = document.getElementById('admin_load_btn');
  if (adminLoadBtn) adminLoadBtn.addEventListener('click', adminLoadTransactions);
  const adminStatsBtn = document.getElementById('admin_stats_btn');
  if (adminStatsBtn) adminStatsBtn.addEventListener('click', adminLoadStats);
  const renameBtn = document.getElementById('rename_person_btn');
  if (renameBtn) renameBtn.addEventListener('click', adminRenamePerson);
});

async function adminLoadTransactions() {
  const q = document.getElementById('admin_search_q').value.trim();
  const order_by = document.getElementById('admin_order_by').value;
  const direction = document.getElementById('admin_direction').value;
  const limit = parseInt(document.getElementById('admin_limit').value || "200", 10);

  const body = { q, order_by, direction, limit };
  const res = await fetch('/api/admin/transactions', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(body),
    credentials: 'same-origin'
  });
  const j = await res.json();
  if (!res.ok) { alert("Error: " + (j.error || JSON.stringify(j))); return; }
  const tbody = document.querySelector("#admin_tx_table tbody");
  const rows = j.transactions || [];
  if (rows.length === 0) { tbody.innerHTML = "<tr><td colspan='7'>No transactions</td></tr>"; return; }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${r.transaction_id}</td>
      <td>${r.transaction_type}</td>
      <td>${r.amount}</td>
      <td>${r.to_account_number || '-'}</td>
      <td>${r.transaction_log}</td>
      <td>${new Date(r.created_at).toLocaleString()}</td>
      <td>${r.account_number}</td>
    </tr>
  `).join('');
  // store last response optionally for debug
  window.lastAdminResponse = j;
}

async function adminLoadStats() {
  const res = await fetch('/api/admin/stats', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    credentials: 'same-origin'
  });
  const j = await res.json();
  if (!res.ok) { alert("Error loading stats: " + (j.error || JSON.stringify(j))); return; }
  const el = document.getElementById('admin_stats');
  el.innerHTML = '<h4>Average amount by transaction type</h4>' + (j.stats || []).map(s => `<div>${s.transaction_type}: AVG=${parseFloat(s.avg_amount).toFixed(2)} (count=${s.cnt})</div>`).join('');
}

async function adminRenamePerson() {
  const person_id = document.getElementById('rename_person_id').value;
  const new_name = document.getElementById('rename_person_name').value.trim();
  if (!person_id || !new_name) return alert('person id and new name required');
  const res = await fetch('/api/admin/rename_person', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ person_id, new_name }),
    credentials: 'same-origin'
  });
  const j = await res.json();
  if (res.ok) { alert("Renamed successfully"); adminLoadTransactions(); }
  else alert("Error: " + (j.error || JSON.stringify(j)));
}
