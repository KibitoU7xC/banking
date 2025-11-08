async function loadUsers() {
  const search = document.getElementById("user_search").value;
  const sort = document.getElementById("user_sort").value;
  const res = await fetch('/api/admin/list_users', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({search, sort, order:'ASC'}),
    credentials: 'same-origin'
  });
  const j = await res.json();
  const el = document.getElementById("users_list");
  if (res.ok) {
    el.innerHTML = j.users.map(u=>
      `<div><strong>${u.name}</strong> (${u.email}) [${u.user_id}]
       <button onclick="deleteUser('${u.user_id}')">Delete</button>
       <button onclick="updateUser('${u.user_id}')">Update</button>
      </div>`
    ).join('');
  } else el.innerText = "Error: " + (j.error || JSON.stringify(j));
}

async function loadTransactions() {
  const order = document.getElementById("tx_order").value;
  const res = await fetch('/api/admin/list_transactions', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({order}),
    credentials: 'same-origin'
  });
  const j = await res.json();
  const el = document.getElementById("tx_list");
  if (res.ok) {
    el.innerHTML = j.transactions.map(tx=>
      `<div>${tx.transaction_id}: ${tx.amount} ${tx.transaction_type} (${tx.account_number}) by ${tx.name} - ${tx.email} @${tx.created_at}</div>`
    ).join('');
  } else el.innerText = "Error: " + (j.error || JSON.stringify(j));
}

async function deleteUser(user_id) {
  if (!confirm("Delete user?")) return;
  await fetch('/api/admin/delete_user', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({user_id}),
    credentials: 'same-origin'
  });
  loadUsers();
}

async function updateUser(user_id) {
  const newname = prompt("Enter new name:");
  if (!newname) return;
  await fetch('/api/admin/update_user', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({user_id, name:newname}),
    credentials: 'same-origin'
  });
  loadUsers();
}

// Initial loads
window.addEventListener('load', loadUsers);
