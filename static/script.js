document.addEventListener("DOMContentLoaded", function () {
  // ─── Modal open/close ──────────────────────────────────
  const yearInput = document.getElementById("pr-year");
  if (yearInput) {
    const yy = new Date().getFullYear().toString().slice(-2);
    yearInput.value = yy;
  }
  
  // Function to show flash messages prominently
  function showFlashMessages() {
    const flashMessages = document.querySelectorAll('.fixed.top-16, .fixed.top-20');
    flashMessages.forEach(msg => {
      // Make sure flash messages are visible
      msg.style.display = 'block';
      msg.style.zIndex = '9999';
      
      // Add a subtle animation to draw attention
      msg.style.animation = 'pulse 2s infinite';
    });
  }
  
  // Show flash messages when page loads
  setTimeout(showFlashMessages, 100);
  // Global variable to store user permissions
  let userPermissions = null;

  // Function to load user permissions
  async function loadUserPermissions() {
    try {
      console.log('🔍 Loading user permissions...');
      const response = await fetch('/api/get_my_permissions', {
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
        }
      });
      
      if (!response.ok) {
        console.error('❌ Response not OK:', response.status, response.statusText);
        return;
      }
      
      const data = await response.json();
      console.log('📡 Response data:', data);
      
      if (data.success) {
        userPermissions = data.permissions;
        console.log('✅ User permissions loaded:', userPermissions);
        updateUIForPermissions(); // Update UI after loading permissions
      } else {
        console.error('❌ Failed to load permissions:', data.error || data.message);
      }
    } catch (error) {
      console.error('❌ Error loading permissions:', error);
    }
  }

  // Load permissions when page loads (with small delay to ensure DOM is ready)
  setTimeout(() => {
    loadUserPermissions();
  }, 100);

  // Function to update UI based on permissions
  function updateUIForPermissions() {
    if (!userPermissions) return;
    
    const permissionMap = {
      'modal-pr': 'purchase_requisition',
      'modal-form': 'purchase_order',
      'modal-status': 'check_status',
      'modal-upload': 'upload_po',
      'modal-retrieve': 'retrieve_po',
      'modal-replace': 'replace_amend_po',
      'modal-filters': 'vendor_lookup',
      'modal-add-project': 'purchase_requisition'
    };
    
    // Update each card based on permissions
    Object.keys(permissionMap).forEach(modalId => {
      const card = document.querySelector(`[data-modal="${modalId}"]`);
      if (card) {
        const hasAccess = userPermissions[permissionMap[modalId]] === true || userPermissions[permissionMap[modalId]] === 1;
        if (!hasAccess) {
          card.style.opacity = '0.5';
          card.style.cursor = 'not-allowed';
          card.title = 'Access Restricted - Contact Admin for Approval';
        } else {
          card.style.opacity = '1';
          card.style.cursor = 'pointer';
          card.title = '';
        }
      }
    });
  }

  // Function to check if user has permission for a specific modal
  function hasPermission(modalId) {
    if (!userPermissions) {
      console.log('⚠️ No permissions loaded yet, allowing access to', modalId);
      return true; // Allow access if permissions not loaded yet
    }
    
    console.log('🔍 Checking permission for modal:', modalId);
    console.log('🔍 Current user permissions:', userPermissions);
    
    // Check if user is admin (admin has access to everything)
    if (userPermissions.is_admin === true) {
      console.log(`🔓 Admin user - granting access to ${modalId}`);
      return true;
    }
    
    const permissionMap = {
      'modal-pr': 'purchase_requisition',
      'modal-form': 'purchase_order',
      'modal-status': 'check_status',
      'modal-upload': 'upload_po',
      'modal-retrieve': 'retrieve_po',
      'modal-replace': 'replace_amend_po',
      'modal-filters': 'vendor_lookup',
      'modal-add-project': 'purchase_requisition' // Project generation requires PR permission
    };
    
    const requiredPermission = permissionMap[modalId];
    if (!requiredPermission) {
      console.log('⚠️ Unknown modal', modalId, '- allowing access');
      return true; // Allow access to unknown modals
    }
    
    const hasAccess = userPermissions[requiredPermission] === true || userPermissions[requiredPermission] === 1;
    console.log(`🔍 Permission check for ${modalId}: ${requiredPermission} = ${userPermissions[requiredPermission]} (hasAccess: ${hasAccess})`);
    return hasAccess;
  }

  // Function to show unauthorized message
  function showUnauthorizedMessage() {
    alert("You are not Authorized to Access this, Please Contact Admin for Approval.");
  }

  function openModal(id) {
    // Check permissions before opening modal
    if (!hasPermission(id)) {
      showUnauthorizedMessage();
      return;
    }
    
    document.getElementById(id).style.display = "flex";
  }
  function closeModal(id) {
    document.getElementById(id).style.display = "none";
  }

  // Card clicks → open corresponding modal
  document.querySelectorAll(".dash-card[data-modal]").forEach(card => {
    card.addEventListener("click", () => {
      const modalId = card.dataset.modal;
      if (!hasPermission(modalId)) {
        showUnauthorizedMessage();
        return;
      }
      openModal(modalId);
    });
  });

  // Close buttons
  document.querySelectorAll(".close").forEach(btn => {
    btn.addEventListener("click", () => closeModal(btn.dataset.modal));
  });

  // Click outside modal-content to close
  window.addEventListener("click", e => {
    if (e.target.classList.contains("modal")) {
      closeModal(e.target.id);
    }
  });

  // ─── Check PR/PO Status ───────────────────────────────
  const prInp  = document.getElementById('status-pr-number');
  const poInp  = document.getElementById('status-po-number');
  const resDiv = document.getElementById('status-result');
  const prBtn  = document.getElementById('check-pr-status');
  const poBtn  = document.getElementById('check-po-status');

  if (prBtn) {
    prBtn.addEventListener('click', () => {
      const pr = prInp.value.trim();
      if (!pr) return alert('Please enter a PR number.');
      fetch(`/status_pr?pr=${encodeURIComponent(pr)}`)
        .then(r => r.json())
        .then(json => {
          resDiv.innerHTML = `<div class="PO-display">${json.message}</div>`;
        })
        .catch(() => {
          resDiv.innerHTML = `<div class="PO-display">Error checking PR status.</div>`;
        });
    });
  }

  if (poBtn) {
    poBtn.addEventListener('click', () => {
      const po = poInp.value.trim();
      if (!po) return alert('Please enter a PO number.');
      fetch(`/status_po?po=${encodeURIComponent(po)}`)
        .then(r => r.json())
        .then(json => {
          let html = `<div class="PO-display">${json.message}</div>`;
          if (json.download_url) {
            html += `<button id="download-status-po" class="btn-primary full-width" style="margin-top:10px;">Download PO</button>`;
          }
          resDiv.innerHTML = html;
          if (json.download_url) {
            document.getElementById('download-status-po')
              .addEventListener('click', () => window.location = json.download_url);
          }
        })
        .catch(() => {
          resDiv.innerHTML = `<div class="PO-display">Error checking PO status.</div>`;
        });
    });
  }


  // ─── Add New Client ───────────────────────────────────────
const clientSelect = document.getElementById('pr-clientcode');
const addClientBtn = document.getElementById('add-client-btn');

if (clientSelect && addClientBtn) {
  addClientBtn.addEventListener('click', () => {
    const name = prompt("Enter new client name:");
    if (!name) return;

    const formData = new FormData();
    formData.append('client_name', name);

    fetch('/add_client', {
      method: 'POST',
      body: formData
    })
    .then(resp => resp.json())
    .then(data => {
      // add new option and select it
      const opt = document.createElement('option');
      opt.value = data.code;
      opt.textContent = data.name;
      clientSelect.appendChild(opt);
      clientSelect.value = data.code;
    })
    .catch(err => {
      console.error(err);
      alert("Failed to add client. See console for details.");
    });
  });
}

 // ─── Open/close the “Generate Project” modal ─────────────────────────
 const addProjBtn = document.querySelector('[data-modal="modal-add-project"]');
   if (addProjBtn) {
    addProjBtn.addEventListener('click', () => {
      if (!hasPermission('modal-add-project')) {
        showUnauthorizedMessage();
        return;
      }
      openModal('modal-add-project');
    });
  }
 
 // ─── Submit Generate Project form via AJAX ──────────────────────────
 const addProjectForm = document.getElementById('addProjectForm');
 if (addProjectForm) {
   addProjectForm.addEventListener('submit', e => {
     e.preventDefault();
     console.log('Add Project form submitted');
     
     const fd = new FormData(addProjectForm);
     
     // Debug: Log form data
     console.log('Form data:');
     for (let [key, value] of fd.entries()) {
       console.log(`${key}: ${value}`);
     }
     
     fetch('/add_project', { 
       method: 'POST', 
       body: fd,
       headers: {
         'X-Requested-With': 'XMLHttpRequest'
       }
     })
       .then(r => {
         console.log('Response status:', r.status);
         if (r.status === 401) {
           // Authentication required
           const data = r.json();
           if (data.redirect) {
             window.location.href = data.redirect;
           }
           return Promise.reject(new Error('Authentication required'));
         }
         return r.json();
       })
       .then(data => {
         console.log('Response data:', data);
         if (data.error) {
           alert(`Error: ${data.error}`);
           return;
         }
         // Add to PR project dropdown
         const prSel = document.getElementById('pr-project-number');
         const prOpt = document.createElement('option');
         prOpt.value = data.project_number;
         prOpt.textContent = data.project_number;
         prSel.appendChild(prOpt);
         prSel.value = data.project_number;
         
         // Add to PO project dropdown
         const poSel = document.getElementById('project_name');
         if (poSel) {
           const poOpt = document.createElement('option');
           poOpt.value = data.project_number;
           poOpt.textContent = data.project_number;
           poSel.appendChild(poOpt);
           poSel.value = data.project_number;
         }
        
        closeModal('modal-add-project');
        // Ensure all UI lists and dependent data refresh
        window.location.reload();
       })
       .catch(err => {
         console.error('Fetch error:', err);
         alert('Failed to generate project number.');
       });
   });
 }


  // ─── Generate Form: dynamic items ───────────────────────
  const poFormModal = document.getElementById("modal-form");
  if (poFormModal) {
    const numItemsInput = poFormModal.querySelector("#num_items");
    const itemsContainer = poFormModal.querySelector("#items_container");
    const projSel = poFormModal.querySelector('#project_name');
    const prSel = poFormModal.querySelector('#po-pr-number');

    // Store budget data globally for this modal instance
    let currentBudgets = {};
    let currentPRDepartment = '';
    let currentPROrderType = ''; // will be set from PR data
    let currentPRItemType = ''; // will be set from PR data

    // Function to update budget display
    function updatePOBudgetDisplay() {
        const indicativePriceInput = poFormModal.querySelector("#po-indicative-price");
        const totalBudgetInput = poFormModal.querySelector("#po-total-budget");
        const remainingBudgetInput = poFormModal.querySelector("#po-remaining-budget");

        let indicativePrice = 0;
        const count = parseInt(numItemsInput.value, 10) || 0;
        for (let i = 1; i <= count; i++) {
            const qty = parseFloat(poFormModal.querySelector(`#item_${i}_quantity`)?.value) || 0;
            const rate = parseFloat(poFormModal.querySelector(`#item_${i}_unit_rate`)?.value) || 0;
            indicativePrice += qty * rate;
        }
        
        indicativePriceInput.value = indicativePrice.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

        // Choose budget column based on PR Order Type
        let budgetKey = 'Material_Budget'; // default fallback
        if (currentPROrderType && currentPROrderType.toLowerCase() === 'services') {
            budgetKey = 'Service_Budget';
        }
        
        console.log('Budget Calculation Debug:');
        console.log('- Current PR Order Type:', currentPROrderType);
        console.log('- Selected Budget Key:', budgetKey);
        console.log('- Available Budgets:', currentBudgets);
        console.log('- Department:', currentPRDepartment);

        const deptBudget = currentBudgets[currentPRDepartment]?.[budgetKey] || 0;
        totalBudgetInput.value = deptBudget.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
        
        const remainingBudget = deptBudget - indicativePrice;
        remainingBudgetInput.value = remainingBudget.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
        
        // Check if NFA is required and show/hide NFA field
        checkNFARequirement(remainingBudget);
    }
    
    // Function to check if NFA is required
    function checkNFARequirement(remainingBudget) {
        const nfaFieldset = poFormModal.querySelector('#nfa-fieldset');
        const nfaFileInput = poFormModal.querySelector('#nfa-file');
        
        // Check if Type of Item is Non-Budgeted or if remaining budget is negative
        const isNonBudgeted = currentPRItemType && currentPRItemType.toLowerCase() === 'non-budgeted';
        const isBudgetExceeded = remainingBudget < 0;
        
        console.log('NFA Requirement Check:');
        console.log('- Current PR Item Type:', currentPRItemType);
        console.log('- Is Non-Budgeted:', isNonBudgeted);
        console.log('- Remaining Budget:', remainingBudget);
        console.log('- Is Budget Exceeded:', isBudgetExceeded);
        
        if (isNonBudgeted || isBudgetExceeded) {
            // Show NFA field and make it required
            nfaFieldset.style.display = 'block';
            nfaFileInput.required = true;
            
            // Update the legend text based on the reason
            const legend = nfaFieldset.querySelector('legend');
            if (isNonBudgeted && isBudgetExceeded) {
                legend.textContent = 'NFA (No Further Action) Document - Required (Non-Budgeted Item & Budget Exceeded)';
            } else if (isNonBudgeted) {
                legend.textContent = 'NFA (No Further Action) Document - Required (Non-Budgeted Item)';
            } else {
                legend.textContent = 'NFA (No Further Action) Document - Required (Budget Exceeded)';
            }
        } else {
            // Hide NFA field and make it not required
            nfaFieldset.style.display = 'none';
            nfaFileInput.required = false;
            nfaFileInput.value = ''; // Clear the file input
        }
    }
    
    // Function to render item fields
    function renderItems() {
      itemsContainer.innerHTML = "";
      const count = parseInt(numItemsInput.value, 10) || 0;
      for (let i = 1; i <= count; i++) {
        itemsContainer.insertAdjacentHTML("beforeend", `
          <fieldset class="item-fieldset">
            <legend>Item ${i}</legend>
            <div class="form-group">
              <label for="item_${i}_name">Item Name</label>
              <input id="item_${i}_name" name="item_${i}_name" required>
            </div>
            <div class="form-group full-width">
              <label for="item_${i}_additional_info">Additional Info</label>
              <textarea id="item_${i}_additional_info" name="item_${i}_additional_info" rows="2" required></textarea>
            </div>
            <div class="items-row">
              <div class="form-group">
                <label for="item_${i}_quantity">QTY</label>
                <input id="item_${i}_quantity" name="item_${i}_quantity" type="number" step="any" required class="po-item-input">
              </div>
              <div class="form-group">
                <label for="item_${i}_uom">UOM</label>
                <input id="item_${i}_uom" name="item_${i}_uom" required>
              </div>
              <div class="form-group">
                <label for="item_${i}_unit_rate">Unit Rate</label>
                <input id="item_${i}_unit_rate" name="item_${i}_unit_rate" type="number" step="any" required class="po-item-input">
              </div>
            </div>
          </fieldset>`);
      }
      // Add event listeners to new inputs
      poFormModal.querySelectorAll('.po-item-input').forEach(input => {
          input.addEventListener('input', updatePOBudgetDisplay);
      });
    }
    
    // Number of items is now readonly - items come from PR
    // numItemsInput.addEventListener("change", () => {
    //     renderItems();
    //     updatePOBudgetDisplay();
    // });
    
    // Initial render
    renderItems();

    // Add vendor lookup functionality
    const vendorCodeInput = poFormModal.querySelector('#vendor_code');
    const companyInput = poFormModal.querySelector('#company');
    const companyAddressInput = poFormModal.querySelector('#company_address');
    const gstInput = poFormModal.querySelector('#gst');
    const contactPersonInput = poFormModal.querySelector('#contact_person_name');
    const contactMobileInput = poFormModal.querySelector('#contact_person_mobile');
    const contactEmailInput = poFormModal.querySelector('#contact_person_email');
    
    if (vendorCodeInput && companyInput && companyAddressInput) {
        // Add event listener for vendor code input
        vendorCodeInput.addEventListener('blur', async function() {
            const vendorCode = this.value.trim();
            if (vendorCode) {
                try {
                    const response = await fetch('/api/vendor_lookup', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify({ vendor_code: vendorCode })
                    });
                    
                    if (response.ok) {
                        const vendorData = await response.json();
                        console.log('Vendor lookup result:', vendorData);
                        
                        // Auto-fill vendor details
                        if (vendorData.company_name) {
                            companyInput.value = vendorData.company_name;
                        }
                        if (vendorData.vendor_address) {
                            companyAddressInput.value = vendorData.vendor_address;
                        }
                        if (vendorData.gst_number && gstInput) {
                            gstInput.value = vendorData.gst_number;
                        }
                        if (vendorData.contact_person && contactPersonInput) {
                            contactPersonInput.value = vendorData.contact_person;
                        }
                        if (vendorData.contact_mobile && contactMobileInput) {
                            contactMobileInput.value = vendorData.contact_mobile;
                        }
                        if (vendorData.contact_email && contactEmailInput) {
                            contactEmailInput.value = vendorData.contact_email;
                        }
                        
                        // Show success message
                        showVendorLookupMessage('Vendor details auto-filled successfully!', 'success');
                    } else {
                        const errorData = await response.json();
                        console.log('Vendor not found:', errorData.error);
                        showVendorLookupMessage('Vendor not found. Please check the vendor code.', 'warning');
                    }
                } catch (error) {
                    console.error('Vendor lookup error:', error);
                    showVendorLookupMessage('Error looking up vendor. Please try again.', 'error');
                }
            }
        });
        
        // Function to show vendor lookup messages
        function showVendorLookupMessage(message, type) {
            // Remove existing message
            const existingMessage = poFormModal.querySelector('.vendor-lookup-message');
            if (existingMessage) {
                existingMessage.remove();
            }
            
            // Create new message
            const messageDiv = document.createElement('div');
            messageDiv.className = `vendor-lookup-message p-3 rounded text-sm ${type === 'success' ? 'bg-green-100 text-green-800' : type === 'warning' ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'}`;
            messageDiv.textContent = message;
            
            // Insert after vendor code input
            vendorCodeInput.parentNode.insertAdjacentElement('afterend', messageDiv);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.remove();
                }
            }, 5000);
        }
    }

    // Fetch PR numbers when a project is selected
    if (projSel && prSel) {
        projSel.addEventListener('change', () => {
            const pid = projSel.value;
            prSel.innerHTML = '<option>Loading…</option>';
            prSel.disabled = true;

            // Fetch budgets for the selected project
            fetch(`/api/v1/pr-budgets?project_number=${encodeURIComponent(pid)}`)
                .then(res => res.json())
                .then(budgets => {
                    currentBudgets = budgets;
                }).catch(() => alert("Could not load project budgets."));

            // Fetch PR numbers for the project
            fetch(`/get_pr_numbers?project_id=${encodeURIComponent(pid)}`)
            .then(res => res.json())
            .then(data => {
                prSel.innerHTML = '<option value="" disabled selected>Select PR Number</option>';
                data.pr_numbers.forEach(pr => {
                const opt = document.createElement('option');
                opt.value = pr;
                opt.textContent = pr;
                prSel.appendChild(opt);
                });
                prSel.disabled = false;
            })
            .catch(() => {
                prSel.innerHTML = '<option value="">Error loading PRs</option>';
            });
        });

        // Fetch and render PR items when a PR is selected
        prSel.addEventListener('change', () => {
            const proj = projSel.value;
            const pr = prSel.value;
        
            fetch(`/api/pr_items?project_number=${encodeURIComponent(proj)}&pr_number=${encodeURIComponent(pr)}`)
            .then(r => r.json())
            .then(data => {
                poFormModal.querySelector("#po_number").value = data.po_number;
                currentPRDepartment = data.department; // Assuming API returns department
                poFormModal.querySelector("#po-department").value = data.department;

                // Try to capture order type and item type from this API if available
                if (data.order_type) {
                    currentPROrderType = String(data.order_type).trim();
                    console.log('PR Order Type from API:', currentPROrderType);
                }
                if (data.item_type) {
                    currentPRItemType = String(data.item_type).trim();
                    console.log('PR Item Type from API:', currentPRItemType);
                }

                // Set number of items from PR data (field is readonly)
                numItemsInput.value = data.items.length || 1;
                renderItems();
                data.items.forEach((it, i) => {
                    const idx = i + 1;
                    poFormModal.querySelector(`#item_${idx}_name`).value = it.name || '';
                    poFormModal.querySelector(`#item_${idx}_additional_info`).value = it.additional_info || '';
                    poFormModal.querySelector(`#item_${idx}_quantity`).value = it.quantity || '';
                    poFormModal.querySelector(`#item_${idx}_uom`).value = it.uom || '';
                    poFormModal.querySelector(`#item_${idx}_unit_rate`).value = it.unit_rate || '';
                });
                updatePOBudgetDisplay(); // Update budget display after loading items

                // If order type or item type wasn't provided, fetch PR details to get them
                if (!data.order_type || !data.item_type) {
                    fetch(`/api/get_pr_details/${encodeURIComponent(pr)}`)
                      .then(resp => resp.ok ? resp.json() : Promise.reject())
                      .then(prInfo => {
                          if (prInfo && prInfo.order_type) {
                              currentPROrderType = String(prInfo.order_type).trim();
                              console.log('PR Order Type from fallback API:', currentPROrderType);
                          }
                          if (prInfo && prInfo.item_type) {
                              currentPRItemType = String(prInfo.item_type).trim();
                              console.log('PR Item Type from fallback API:', currentPRItemType);
                          }
                          updatePOBudgetDisplay();
                      })
                      .catch(() => {/* ignore */});
                }
            })
            .catch(console.error);
        });
    }
}

  // ─── Upload PO AJAX ─────────────────────────────────────
  const uploadForm = document.getElementById("uploadPOForm");
  if (uploadForm) {
    uploadForm.addEventListener("submit", e => {
      e.preventDefault();
      const fd = new FormData(uploadForm);
      fetch(uploadForm.action, { method: "POST", body: fd })
        .then(r => r.json())
        .then(d => {
            alert(d.message);
            fetchDashboardStats(); // Add this line
            renderPOCharts();      // And this line
        })
        .catch(() => alert("Upload error"));
    });
  }

  // ─── Replace PO AJAX ────────────────────────────────────
  const replaceForm = document.getElementById("replacePOForm");
  if (replaceForm) {
    replaceForm.addEventListener("submit", e => {
      e.preventDefault();
      const fd = new FormData(replaceForm);
      fetch(replaceForm.action, { method: "POST", body: fd })
        .then(r => r.json())
        .then(d => {
            alert(d.message)
            fetchDashboardStats(); // Add this line
            renderPOCharts();      // And this line
        })
        .catch(() => alert("Replace error"));
    });
  }


  // When “Retrieve PO” card is clicked, fetch & render all PO records:
  document
  .querySelector('.dash-card[data-modal="modal-retrieve"]')
  .addEventListener("click", () => {
    fetch("/get_all_pos")
      .then(r => r.json())
      .then(list => {
        const container = document.getElementById("retrieve_list");
        container.innerHTML = "";
        if (!list.length) {
          container.innerHTML = "<p>No PO records found.</p>";
          return;
        }
        list.forEach((rec, idx) => {
          const div = document.createElement("div");
          div.className = "PO-record";
          div.innerHTML = `
            <p><strong>${idx + 1}.</strong> <strong>PO:</strong> ${rec["PO Number"]}</p>
            <p><strong>Date:</strong> ${rec.Date}</p>
            <p><strong>Company Name:</strong> ${rec["Company Name"]}</p>
            <p><strong>Total Amount:</strong> ${rec["Total Amount"]}</p>
            <form action="/retrieve_PO" method="POST">
              <input type="hidden" name="PO_number" value="${rec["PO Number"]}">
              <button type="submit" class="btn-secondary bg-blue-500 text-white mb-4" style="padding: var(--spacing-sm);">Download</button>
            </form>
            <hr>`;
          container.appendChild(div);
        });
      });
  });


const filtersForm = document.getElementById("filtersForm");
if (filtersForm) {
  filtersForm.addEventListener("submit", e => {
    e.preventDefault();
    const searchType = document.getElementById("filter_search_type").value;
    const searchTerm = document.getElementById("filter_search_term").value.trim();
    console.log("🔍 Fetching /api/vendor_search for", searchType, "=", searchTerm);
    
    if (!searchTerm) {
      alert("Please enter a search term");
      return;
    }
    
    fetch("/api/vendor_search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        search_type: searchType,
        search_term: searchTerm 
      })
    })
    .then(r => {
      console.log("↩ status:", r.status);
      if (!r.ok) {
        throw new Error(`HTTP error! status: ${r.status}`);
      }
      return r.json();
    })
    .then(data => {
      console.log("↩ data:", data);
      const container = document.getElementById("filters_results");
      
      if (!data.items || data.items.length === 0) {
        container.innerHTML = `<p style='text-align: center; color: #666; padding: 20px;'>No items found for ${searchType === 'code' ? 'vendor code' : 'company name'}: ${searchTerm}</p>`;
        return;
      }
      
      container.innerHTML = `
        <div style="margin-top: 16px;">
          <h4 style="margin-bottom: 12px; color: #333;">Items Found (${data.items.length})</h4>
          <div style="max-height: 400px; overflow-y: auto;">
            ${data.items.map(item => `
              <div style="border: 1px solid #ddd; padding: 16px; margin-bottom: 12px; border-radius: 6px; background: #f9f9f9;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                  <strong style="color: #2c3e50; font-size: 16px;">${item.item_name || 'N/A'}</strong>
                  <span style="background: #3498db; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px;">${item.vendor_code}</span>
                </div>
                <div style="font-size: 14px; color: #555;">
                  <div><strong>Company:</strong> ${item.company_name || 'N/A'}</div>
                  <div><strong>Additional Info:</strong> ${item.additional_info || 'N/A'}</div>
                </div>
              </div>
            `).join("")}
          </div>
        </div>`;
    })
    .catch(err => {
      console.error("❌ /api/vendor_search error", err);
      document.getElementById("filters_results")
              .innerHTML = "<p style='text-align: center; color: #dc3545; padding: 20px;'>Error fetching data. Please try again.</p>";
    });
  });
}


   // ─── PR: dynamic items + budgets calc ──────────────────
   const prNumItemsInput = document.getElementById("pr-num_items");
   const prItemsContainer = document.getElementById("pr_items_container");
   const prSection = document.getElementById("pr-section");
 
   if (prNumItemsInput && prItemsContainer && prSection) {
    const deptSelect     = document.getElementById("pr-department");
    const deptCodeInput  = document.getElementById("pr-department-code");
    const projectNumberSelect = document.getElementById("pr-project-number");
    
    // Function to fetch and auto-fill project name
    async function fetchProjectDetails(projectNumber) {
      const projectNameInput = document.getElementById("pr-project_name");
      if (!projectNameInput) return;

      if (!projectNumber) {
        projectNameInput.value = '';
        return;
      }
      
      try {
        const response = await fetch(`/api/v1/project-details?project_number=${encodeURIComponent(projectNumber)}`);
        if (response.ok) {
          const projectData = await response.json();
          projectNameInput.value = projectData.found ? projectData.project_name : '';
        } else {
          projectNameInput.value = '';
          console.error('Failed to fetch project details');
        }
      } catch (error) {
        projectNameInput.value = '';
        console.error('Error fetching project details:', error);
      }
    }
    
    if (projectNumberSelect) {
      projectNumberSelect.addEventListener('change', function() {
        fetchProjectDetails(this.value.trim());
      });
    }

    // Excel upload for PR items → auto-fill
    const prItemsExcel = document.getElementById('pr-items-excel');
    const globalLoading = document.getElementById('global-loading');
    if (prItemsExcel) {
      prItemsExcel.addEventListener('change', async function() {
        const file = this.files && this.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        try {
          if (globalLoading) globalLoading.style.display = 'flex';
          const resp = await fetch('/api/pr_upload_items', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
          });
          const json = await resp.json();
          if (!json.success) {
            alert(json.message || 'Failed to parse Excel.');
            return;
          }
          const num = parseInt(json.num_items || 0, 10);
          if (Number.isFinite(num) && num > 0) {
            prNumItemsInput.value = String(num);
            renderPRItems();
            // Fill fields
            json.items.forEach((it, idx) => {
              const i = idx + 1;
              const nameEl = document.getElementById(`pr_item_${i}_name`);
              const descEl = document.getElementById(`pr_item_${i}_description`);
              const qtyEl  = document.getElementById(`pr_item_${i}_unit_items`);
              const uomEl  = document.getElementById(`pr_item_${i}_measurement`);
              if (nameEl) nameEl.value = it.item_name || '';
              if (descEl) descEl.value = it.item_description || '';
              if (qtyEl && (it.quantity || it.quantity === 0)) qtyEl.value = it.quantity;
              if (uomEl && it.uom) {
                const val = String(it.uom).trim();
                // Set existing option if matches (case-insensitive), else add custom
                let matched = false;
                for (const opt of Array.from(uomEl.options)) {
                  if (opt.text.trim().toLowerCase() === val.toLowerCase()) {
                    uomEl.value = opt.value;
                    matched = true;
                    break;
                  }
                }
                if (!matched && val) {
                  const opt = document.createElement('option');
                  opt.value = val;
                  opt.textContent = val;
                  uomEl.appendChild(opt);
                  uomEl.value = val;
                }
              }
            });
          } else {
            alert('No items detected in the uploaded Excel.');
          }
        } catch (e) {
          console.error('pr-items-excel upload error', e);
          alert('Error uploading Excel.');
        } finally {
          if (globalLoading) globalLoading.style.display = 'none';
        }
      });
    }
 
     function renderPRItems() {
       prItemsContainer.innerHTML = "";
       const count = parseInt(prNumItemsInput.value, 10) || 0;
       for (let i = 1; i <= count; i++) {
         prItemsContainer.insertAdjacentHTML("beforeend", `
           <fieldset class="item-fieldset">
             <legend>Item ${i}</legend>
             <div class="form-group full-width">
               <label for="pr_item_${i}_name">Item Name</label>
               <input id="pr_item_${i}_name" name="item_${i}_name" required>
             </div>
             <div class="form-group full-width">
               <label for="pr_item_${i}_description">Item Description</label>
               <textarea id="pr_item_${i}_description" name="item_${i}_description" rows="2" required></textarea>
             </div>
            <div class="items-row">
               <div class="form-group">
                 <label for="pr_item_${i}_unit_items">QTY</label>
                <input id="pr_item_${i}_unit_items" name="item_${i}_unit_items" type="number" step="any" min="0" value="1" required>
               </div>
               <div class="form-group">
                 <label for="pr_item_${i}_measurement">UOM</label>
                 <select id="pr_item_${i}_measurement" name="item_${i}_measurement" required>
                   <option value="" disabled selected>Select</option>
                   <option>Nos</option>
                   <option>Kg</option>
                   <option>Meter</option>
                 </select>
               </div>
             </div>
           </fieldset>
         `);
       }
       hookPRInputs();
     }

     function updatePR() {
        // This function now only sets the department code based on selection.
        if (!deptSelect.value) {
            deptCodeInput.value = "";
            return;
        }
        deptCodeInput.value = deptSelect.selectedOptions[0].dataset.code;
     }
 
     function hookPRInputs() {
       deptSelect.addEventListener("change", updatePR);
       updatePR();
     }
 
     prNumItemsInput.addEventListener("change", renderPRItems);
 
     document.querySelector('.dash-card[data-modal="modal-pr"]')
             .addEventListener("click", () => {
               renderPRItems();
               updatePR();
             });
   }

   // ─── View PR Section ─────────────────────────────────────
   const prSidebar = document.querySelector('.pr-sidebar nav ul');
   if (prSidebar) {
     const generatePRLink = prSidebar.querySelector('li:first-child a');
     const viewPRLink = prSidebar.querySelector('li:last-child a');
     
     if (generatePRLink && viewPRLink) {
       generatePRLink.addEventListener('click', (e) => {
         e.preventDefault();
         showPRSection('generate');
       });
       
       viewPRLink.addEventListener('click', (e) => {
         e.preventDefault();
         showPRSection('view');
       });
     }
   }

   function showPRSection(section) {
     const generateSection = document.getElementById('generate-pr-section');
     const viewSection = document.getElementById('view-pr-section');
     const generateLink = document.querySelector('.pr-sidebar nav ul li:first-child a');
     const viewLink = document.querySelector('.pr-sidebar nav ul li:last-child a');
     
     if (section === 'generate') {
       generateSection.style.display = 'block';
       viewSection.style.display = 'none';
       generateLink.classList.add('active');
       viewLink.classList.remove('active');
     } else {
       generateSection.style.display = 'none';
       viewSection.style.display = 'block';
       viewLink.classList.add('active');
       generateLink.classList.remove('active');
       loadPRs();
     }
   }

   function loadPRs() {
     const container = document.getElementById('pr-list-container');
     container.innerHTML = `
       <div class="text-center py-8">
         <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
         <p class="text-gray-600">Loading PRs...</p>
       </div>
     `;

     fetch('/get_all_prs', {
       headers: {
         'X-Requested-With': 'XMLHttpRequest'
       }
     })
     .then(response => response.json())
     .then(data => {
       if (data.error) {
         container.innerHTML = `<div class="text-center py-8 text-red-600">Error: ${data.error}</div>`;
         return;
       }
       
       if (!data || data.length === 0) {
         container.innerHTML = `
           <div class="text-center py-8">
             <div class="text-gray-600 mb-4">No rejected PRs found</div>
             <p class="text-sm text-gray-500">All PRs are either approved or pending approval</p>
           </div>
         `;
         return;
       }

       // Store all data globally for editing (including all item rows)
       window.allPRData = data;
       
       // Create unique PRs for display (deduplicate by PR Number)
       const uniquePRs = [];
       const seenPRs = new Set();
       
       data.forEach(pr => {
         if (!seenPRs.has(pr['PR Number'])) {
           seenPRs.add(pr['PR Number']);
           uniquePRs.push(pr);
         }
       });

       let html = `
         <div class="overflow-x-auto">
           <table class="w-full border-collapse border border-gray-300">
             <thead>
               <tr class="bg-gray-100">
                 <th class="border border-gray-300 px-4 py-2 text-left">PR Number</th>
                 <th class="border border-gray-300 px-4 py-2 text-left">Project</th>
                 <th class="border border-gray-300 px-4 py-2 text-left">Department</th>
                 <th class="border border-gray-300 px-4 py-2 text-left">Requester</th>
                 <th class="border border-gray-300 px-4 py-2 text-left">Status</th>
                 <th class="border border-gray-300 px-4 py-2 text-left">Date</th>
                 <th class="border border-gray-300 px-4 py-2 text-left">Actions</th>
               </tr>
             </thead>
             <tbody>
       `;

       uniquePRs.forEach(pr => {
         html += `
           <tr class="hover:bg-gray-50">
             <td class="border border-gray-300 px-4 py-2">${pr['PR Number'] || 'N/A'}</td>
             <td class="border border-gray-300 px-4 py-2">${pr['Project Number'] || 'N/A'}</td>
             <td class="border border-gray-300 px-4 py-2">${pr['Requisition Department'] || 'N/A'}</td>
             <td class="border border-gray-300 px-4 py-2">${pr['Name'] || 'N/A'}</td>
             <td class="border border-gray-300 px-4 py-2">
               <span class="px-2 py-1 rounded text-xs ${
                 pr['PR Status'] === 'Approved' ? 'bg-green-100 text-green-800' :
                 pr['PR Status'] === 'Rejected' ? 'bg-red-100 text-red-800' :
                 'bg-yellow-100 text-yellow-800'
               }">
                 ${pr['PR Status'] || 'Pending'}
               </span>
             </td>
             <td class="border border-gray-300 px-4 py-2">${pr['Date'] || 'N/A'}</td>
             <td class="border border-gray-300 px-4 py-2">
               <button onclick="editPR('${pr['PR Number']}')" class="btn-secondary bg-blue-500 text-white text-sm px-3 py-1">
                 Edit
               </button>
             </td>
           </tr>
         `;
       });

       html += `
             </tbody>
           </table>
         </div>
       `;

       container.innerHTML = html;
     })
     .catch(error => {
       console.error('Error loading PRs:', error);
       container.innerHTML = `<div class="text-center py-8 text-red-600">Error loading PRs</div>`;
     });
   }

   // Make editPR function global
   window.editPR = function(prNumber) {
     // Use the global data that was already loaded
     const data = window.allPRData;
     if (!data) {
       alert('PR data not loaded. Please refresh the page.');
       return;
     }
     
     const pr = data.find(p => p['PR Number'] === prNumber);
     if (!pr) {
       alert('PR not found');
       return;
     }
     
     // Populate edit form
     document.getElementById('edit-pr-project-number').value = pr['Project Number'] || '';
     document.getElementById('edit-pr-project-name').value = pr['Project Name'] || '';
     document.getElementById('edit-pr-department').value = pr['Requisition Department'] || '';
     document.getElementById('edit-pr-discipline').value = pr['Discipline'] || '';
     document.getElementById('edit-pr-order-type').value = pr['Order Type'] || '';
     document.getElementById('edit-pr-requester-role').value = pr['Name'] || '';
     document.getElementById('edit-pr-email').value = pr['Requester Email'] || '';
     document.getElementById('edit-pr-date').value = pr['Date'] || '';
     document.getElementById('edit-pr-expected-delivery').value = pr['Expected Delivery Date'] || '';
     document.getElementById('edit-pr-priority').value = pr['Priority of PO'] || '';
     
     // Get the number of items from the saved data
     const numItems = parseInt(pr['Number of Items'] || '1');
     document.getElementById('edit-pr-num-items').value = numItems;
     
     document.getElementById('edit-pr-material-file').value = pr['Material Requisition File'] || '';
     
     // Clear the new file input
     document.getElementById('edit-pr-material-file-new').value = '';
     
     // Store PR number for update
     document.getElementById('edit-pr-form').dataset.prNumber = prNumber;
     
     // Store current PR data globally for number of items change handler
     window.currentEditingPR = pr;
     
     // Get all items for this PR (all rows with the same PR Number)
     const prItems = data.filter(p => p['PR Number'] === prNumber);
     window.currentEditingPRItems = prItems;
     
     console.log('PR Items found:', prItems);
     console.log('Number of items:', numItems);
     
     // Debug: Show each row's item data
     prItems.forEach((item, index) => {
       console.log(`Row ${index}:`, {
         'Item Name': item['Item Name'],
         'Item Description': item['Item Description'],
         'Unit of Items': item['Unit of Items'],
         'Measurement': item['Measurement']
       });
     });
     
     // Render items with correct number
     renderEditPRItems(pr, numItems);
     
     // Open modal
     document.getElementById('modal-edit-pr').style.display = 'flex';
   };

   function renderEditPRItems(pr, numItems = null) {
     const container = document.getElementById('edit-pr-items-container');
     // Use passed numItems or fall back to the saved value
     if (numItems === null) {
       numItems = parseInt(pr['Number of Items'] || '1');
     }
     
     container.innerHTML = '';
     
     // Get all items for this PR from the current data
     const currentPRItems = window.currentEditingPRItems || [];
     
     for (let i = 1; i <= numItems; i++) {
       // Find the corresponding item data
       // Each row in currentPRItems represents one item
       let itemData;
       
       if (currentPRItems.length >= i) {
         // Use the i-th row (index i-1) for the i-th item
         itemData = currentPRItems[i-1];
         console.log(`Item ${i} using row ${i-1}:`, itemData);
       } else {
         // Fallback to base PR data if not enough rows
         itemData = pr;
         console.log(`Item ${i} using fallback data:`, itemData);
       }
       
       console.log(`Item ${i} final data:`, {
         'Item Name': itemData['Item Name'],
         'Item Description': itemData['Item Description'],
         'Unit of Items': itemData['Unit of Items'],
         'Measurement': itemData['Measurement']
       });
       
       container.insertAdjacentHTML('beforeend', `
         <fieldset class="item-fieldset">
           <legend>Item ${i}</legend>
           <div class="form-group full-width">
             <label for="edit_pr_item_${i}_name">Item Name</label>
             <input id="edit_pr_item_${i}_name" name="item_${i}_name" value="${itemData['Item Name'] || ''}" required>
           </div>
           <div class="form-group full-width">
             <label for="edit_pr_item_${i}_description">Item Description</label>
             <textarea id="edit_pr_item_${i}_description" name="item_${i}_description" rows="2" required>${itemData['Item Description'] || ''}</textarea>
           </div>
           <div class="items-row">
             <div class="form-group">
               <label for="edit_pr_item_${i}_unit_items">QTY</label>
               <input id="edit_pr_item_${i}_unit_items" name="item_${i}_unit_items" type="number" min="1" value="${itemData['Unit of Items'] || '1'}" required>
             </div>
             <div class="form-group">
               <label for="edit_pr_item_${i}_measurement">UOM</label>
               <select id="edit_pr_item_${i}_measurement" name="item_${i}_measurement" required>
                 <option value="" disabled>Select</option>
                 <option value="Nos" ${itemData['Measurement'] === 'Nos' ? 'selected' : ''}>Nos</option>
                 <option value="Kg" ${itemData['Measurement'] === 'Kg' ? 'selected' : ''}>Kg</option>
                 <option value="Meter" ${itemData['Measurement'] === 'Meter' ? 'selected' : ''}>Meter</option>
               </select>
             </div>
           </div>
         </fieldset>
       `);
     }
   }

   // Add event listener for number of items change
   const editPRNumItemsInput = document.getElementById('edit-pr-num-items');
   if (editPRNumItemsInput) {
     editPRNumItemsInput.addEventListener('change', function() {
       const numItems = parseInt(this.value) || 1;
       const pr = window.currentEditingPR; // Store this when editing
       if (pr) {
         renderEditPRItems(pr, numItems);
       }
     });
   }

   // Handle edit PR form submission
   const editPRForm = document.getElementById('edit-pr-form');
   if (editPRForm) {
     editPRForm.addEventListener('submit', function(e) {
       e.preventDefault();
       
       const prNumber = this.dataset.prNumber;
       if (!prNumber) {
         alert('PR Number not found');
         return;
       }
       
       const formData = new FormData(this);
       formData.append('pr_number', prNumber);
       
       // Show loading state
       const submitBtn = this.querySelector('button[type="submit"]');
       const originalText = submitBtn.textContent;
       submitBtn.textContent = 'Updating...';
       submitBtn.disabled = true;
       
       fetch('/update_pr', {
         method: 'POST',
         headers: {
           'X-Requested-With': 'XMLHttpRequest'
         },
         body: formData
       })
       .then(response => response.json())
       .then(result => {
         if (result.success) {
           alert('PR updated successfully and sent for re-approval');
           document.getElementById('modal-edit-pr').style.display = 'none';
           loadPRs(); // Refresh the PR list
         } else {
           alert('Error updating PR: ' + result.message);
         }
       })
       .catch(error => {
         console.error('Error updating PR:', error);
         alert('Error updating PR');
       })
       .finally(() => {
         // Reset button state
         submitBtn.textContent = originalText;
         submitBtn.disabled = false;
       });
     });
   }

   const itemTypeSelect   = document.getElementById('pr-item-type');
const budgetFieldset   = document.querySelector('.budget-fieldset');
const nfaInput         = document.getElementById('pr-nfa');
const remainingInput = document.getElementById("pr-remaining_budget");
const indInput       = document.getElementById("pr-indicative_price");
const deptSelect      = document.getElementById("pr-department");
// show/hide budget section and enforce NFA upload
function updateItemType() {
  if (!deptSelect || !itemTypeSelect || !indInput || !budgetFieldset || !nfaInput || !remainingInput) {
    return;
  }
  const dept  = deptSelect.value;
  const type = itemTypeSelect.value;
  const ind   = parseFloat(indInput.value.replace(/,/g,'')) || 0;
  // parse Remaining Budget if needed
  nfaInput.required = false;
  if (type === 'non-budgeted') {
    // no budget for non-budgeted
    budgetFieldset.style.display = 'none';
    nfaInput.required = true;
  } 
  if (dept === 'Procurement' && type === 'budgeted' && ind > 1_000_000) {
    nfaInput.required = true;
  }
  else { // budgeted
    budgetFieldset.style.display = '';
    // parse remaining (remove commas)
    const remRaw = remainingInput.value.replace(/,/g, '');
    const rem    = parseFloat(remRaw) || 0;
    // only require NFA when negative
    nfaInput.required = rem < 0;
  }
}

// re-run whenever item type changes
if (itemTypeSelect) {
  itemTypeSelect.addEventListener('change', () => {
    if (typeof updatePR === 'function') updatePR();
    updateItemType();
  });
}
if (deptSelect) {
  deptSelect.addEventListener('change', updateItemType);
}
if (indInput) {
  indInput.addEventListener('input',  updateItemType);
}

// ─── PO Options Tab Management ─────────────────────────────
  const poOptionsModal = document.getElementById('modal-form');
  if (poOptionsModal) {
    const tabGenerate = document.getElementById('tab-generate-po');
    const tabEdit = document.getElementById('tab-edit-po');
    const tabPriority = document.getElementById('tab-check-priority');
    const slider = document.querySelector('.po-options-slider');
    
    const sections = {
      'tab-generate-po': 'generate-po-section',
      'tab-edit-po': 'edit-po-section',
      'tab-check-priority': 'check-priority-section'
    };
    
    function switchPOTab(activeTab) {
      // Update slider position
      const tabWidth = 100 / 3; // 33.333%
      const tabIndex = Array.from([tabGenerate, tabEdit, tabPriority]).indexOf(activeTab);
      slider.style.transform = `translateX(${tabIndex * 100}%)`;
      
      // Update tab styles
      [tabGenerate, tabEdit, tabPriority].forEach(tab => {
        tab.classList.remove('active');
        tab.style.color = '#64748b';
      });
      activeTab.classList.add('active');
      activeTab.style.color = 'white';
      
      // Show/hide sections
      Object.values(sections).forEach(sectionId => {
        const section = document.getElementById(sectionId);
        if (section) {
          section.style.display = 'none';
        }
      });
      
      const activeSection = document.getElementById(sections[activeTab.id]);
      if (activeSection) {
        activeSection.style.display = 'block';
      }
      
      // Load data for specific tabs
      if (activeTab.id === 'tab-edit-po') {
        loadRejectedPOs();
      } else if (activeTab.id === 'tab-check-priority') {
        // Priority data will be loaded when user clicks the button
      }
    }
    
    if (tabGenerate) tabGenerate.addEventListener('click', () => switchPOTab(tabGenerate));
    if (tabEdit) tabEdit.addEventListener('click', () => switchPOTab(tabEdit));
    if (tabPriority) tabPriority.addEventListener('click', () => switchPOTab(tabPriority));
    
    // Check for flash messages when PO modal opens
    const poModal = document.getElementById('modal-form');
    if (poModal) {
      // Function to check and display flash messages in PO modal
      function checkFlashMessagesInPO() {
        const errorMessages = document.querySelectorAll('.fixed.top-16 .text-red-700, .fixed.top-20 .text-red-700');
        const errorDisplay = document.getElementById('po-error-display');
        const errorMessage = document.getElementById('po-error-message');
        
        if (errorMessages.length > 0 && errorDisplay && errorMessage) {
          // Get the first error message
          const errorText = errorMessages[0].textContent.trim();
          errorMessage.textContent = errorText;
          errorDisplay.classList.remove('hidden');
          
          // Scroll to the error message
          errorDisplay.scrollIntoView({ behavior: 'smooth', block: 'center' });
          
          // Make the error message more prominent
          errorDisplay.style.animation = 'pulse 2s infinite';
          errorDisplay.style.border = '2px solid #dc2626';
          errorDisplay.style.boxShadow = '0 0 15px rgba(220, 38, 38, 0.3)';
        } else if (errorDisplay) {
          errorDisplay.classList.add('hidden');
        }
      }
      
      // Check for flash messages when modal opens
      const originalOpenModal = window.openModal;
      window.openModal = function(modalId) {
        if (modalId === 'modal-form') {
          setTimeout(checkFlashMessagesInPO, 100);
        }
        if (originalOpenModal) {
          originalOpenModal(modalId);
        }
      };
      
      // Also check when the Generate PO tab is clicked
      const generateTab = document.getElementById('tab-generate-po');
      if (generateTab) {
        generateTab.addEventListener('click', () => {
          setTimeout(checkFlashMessagesInPO, 200);
        });
      }
    }
    
    // Load rejected POs for editing
    function loadRejectedPOs() {
      const selectElement = document.getElementById('edit-po-number');
      if (!selectElement) return;
      
      // Clear existing options except the first one
      selectElement.innerHTML = '<option value="" disabled selected>Select a rejected PO to edit</option>';
      
      fetch('/api/get_rejected_pos')
        .then(response => response.json())
        .then(data => {
          if (data.success && data.purchase_orders) {
            data.purchase_orders.forEach(po => {
              const option = document.createElement('option');
              option.value = po.po_number;
              option.textContent = `${po.po_number} - ${po.project_name} (${po.po_date})`;
              selectElement.appendChild(option);
            });
          } else {
            const option = document.createElement('option');
            option.value = '';
            option.textContent = 'No rejected POs found';
            option.disabled = true;
            selectElement.appendChild(option);
          }
        })
        .catch(error => {
          console.error('Error loading rejected POs:', error);
          const option = document.createElement('option');
          option.value = '';
          option.textContent = 'Error loading POs';
          option.disabled = true;
          selectElement.appendChild(option);
        });
    }
    
    // Handle PO selection for editing
    const editPOSelect = document.getElementById('edit-po-number');
    if (editPOSelect) {
      editPOSelect.addEventListener('change', function() {
        const poNumber = this.value;
        if (poNumber) {
          loadPOForEditing(poNumber);
        } else {
          document.getElementById('edit-po-form-container').style.display = 'none';
        }
      });
    }
    
    // Load PO data for editing
    function loadPOForEditing(poNumber) {
      const container = document.getElementById('edit-po-form-container');
      if (!container) return;
      
      container.innerHTML = '<div class="text-center py-4"><div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div><p class="text-gray-600">Loading PO data...</p></div>';
      container.style.display = 'block';
      
      fetch(`/api/get_po_full/${poNumber}`)
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            populateEditPOFormFull(data);
          } else {
            container.innerHTML = `<div class="text-center py-4 text-red-600">Error: ${data.message}</div>`;
          }
        })
        .catch(error => {
          console.error('Error loading PO for editing:', error);
          container.innerHTML = '<div class="text-center py-4 text-red-600">Error loading PO data</div>';
        });
    }
    
    // Note: populateEditPOForm() removed - use populateEditPOFormFull() for comprehensive form

    // New: Populate full edit form mirroring Generate PO with budget panel and charges
    function populateEditPOFormFull(full) {
      const container = document.getElementById('edit-po-form-container');
      if (!container) return;
      const po = full.po || {}; const pr = full.pr || {}; const items = full.items || []; const budget = full.budget || {};
      
      console.log('[Edit PO] Received data:', { po, pr, items, budget });
      console.log('[Edit PO] Items count:', items.length);

      container.innerHTML = `
        <form id="edit-po-form" action="/update_po" method="post" enctype="multipart/form-data" class="form-container">
          <input type="hidden" name="po_number" value="${po.po_number || ''}">
          
          <!-- Project and Basic Info Section -->
          <div class="form-section">
            <h3 class="section-title">
              <i class="fas fa-info-circle"></i>
              Basic Information
            </h3>
            <div class="grid-3">
              <div class="form-group">
                <label>Project Name</label>
                <input type="text" value="${po.project_name || pr.project_name || ''}" readonly>
              </div>
              <div class="form-group">
                <label>PR Number</label>
                <input type="text" name="pr_number" value="${po.pr_number || ''}" readonly>
              </div>
              <div class="form-group">
                <label>PO Number</label>
                <input type="text" value="${po.po_number || ''}" readonly>
              </div>
            </div>
            <div class="grid-2-compact">
              <div class="form-group">
                <label>Requester Role</label>
                <select name="po_requester_role" required>
                  ${['CEO','CFO','Head of Procurement','Head of Project Planning and Control','Head of Engineering','Site Head Mechanical'].map(r => `<option ${po.po_requester_role===r?'selected':''}>${r}</option>`).join('')}
                </select>
              </div>
              <div class="form-group">
                <label>Requester Email</label>
                <input type="email" name="po_requester_email" value="${po.po_requester_email||''}" required>
              </div>
              <div class="form-group">
                <label>PO Date</label>
                <input type="date" name="po_date" value="${po.po_date||''}">
              </div>
              <div class="form-group">
                <label>Delivery Date</label>
                <input type="date" name="delivery_date" value="${po.delivery_date||''}">
              </div>
            </div>
          </div>

          <!-- Vendor Information Section -->
          <div class="form-section">
            <h3 class="section-title">
              <i class="fas fa-building"></i>
              Vendor Information
            </h3>
            <div class="grid-2-compact">
              <div class="form-group">
                <label>Vendor Code</label>
                <input name="vendor_code" value="${po.vendor_code||''}" readonly>
              </div>
              <div class="form-group">
                <label>Vendor Name</label>
                <input name="company" value="${po.company||''}" readonly>
              </div>
            </div>
            <div class="form-group full-width">
              <label>Vendor Address</label>
              <textarea name="company_address" rows="2">${po.company_address||''}</textarea>
            </div>
            <div class="grid-3">
              <div class="form-group">
                <label>GST Number</label>
                <input name="gst" value="${po.gst||''}">
              </div>
              <div class="form-group">
                <label>Contact Person</label>
                <input name="contact_person_name" value="${po.contact_person_name||''}">
              </div>
              <div class="form-group">
                <label>Contact Mobile</label>
                <input name="contact_person_mobile" value="${po.contact_person_mobile||''}">
              </div>
            </div>
            <div class="grid-3">
              <div class="form-group">
                <label>Contact Email</label>
                <input name="contact_person_email" value="${po.contact_person_email||''}">
              </div>
              <div class="form-group">
                <label>Your Reference</label>
                <input name="your_reference" value="${po.your_reference||''}">
              </div>
              <div class="form-group">
                <label>Price Basis (INCOTERMS)</label>
                <input name="price_basis" value="${po.price_basis||''}">
              </div>
            </div>
            <div class="form-group">
              <label>Payment Terms</label>
              <input name="payment_term" value="${po.payment_term||''}">
            </div>
          </div>

          <!-- Shipping Information Section -->
          <div class="form-section">
            <h3 class="section-title">
              <i class="fas fa-shipping-fast"></i>
              Shipping Information
            </h3>
            <div class="grid-2-compact">
              <div class="form-group">
                <label>Ship To (Location)</label>
                <input name="ship_to_location" value="${po.ship_to_location||''}">
              </div>
              <div class="form-group">
                <label>Ship To GSTIN</label>
                <input name="ship_to_gstin" value="${po.ship_to_gstin||''}">
              </div>
            </div>
            <div class="form-group full-width">
              <label>Ship To Address</label>
              <textarea name="ship_to_address" rows="2">${po.ship_to_address||''}</textarea>
            </div>
            <div class="grid-2-compact">
              <div class="form-group">
                <label>Bill To Company</label>
                <input name="bill_to_company" value="${po.bill_to_company||''}">
              </div>
              <div class="form-group">
                <label>Bill To GSTIN</label>
                <input name="bill_to_gstin" value="${po.bill_to_gstin||''}">
              </div>
            </div>
            <div class="form-group full-width">
              <label>Bill To Address</label>
              <textarea name="bill_to_address" rows="2">${po.bill_to_address||''}</textarea>
            </div>
          </div>

          <!-- Items Section -->
          <div class="form-section">
            <h3 class="section-title">
              <i class="fas fa-boxes"></i>
              Items Information
            </h3>
            <div class="form-group">
              <label>Number of Items</label>
              <input id="edit-num-items" name="number_of_items" type="number" min="1" value="${po.number_of_items||items.length||1}" required>
            </div>
            <div id="edit-items-container" class="items-grid">
              ${items.map((item, index) => `
                <fieldset class="item-fieldset">
                  <legend>Item ${index + 1}</legend>
                  <div class="form-group">
                    <label for="edit-item-${index + 1}-name">Item Name</label>
                    <input type="text" id="edit-item-${index + 1}-name" name="item_${index + 1}_name" value="${item.item_name || ''}" required>
                  </div>
                  <div class="form-group full-width">
                    <label for="edit-item-${index + 1}-additional-info">Additional Info</label>
                    <textarea id="edit-item-${index + 1}-additional-info" name="item_${index + 1}_additional_info" rows="2" required>${item.additional_info || ''}</textarea>
                  </div>
                  <div class="items-row">
                    <div class="form-group">
                      <label for="edit-item-${index + 1}-quantity">QTY</label>
                      <input type="number" id="edit-item-${index + 1}-quantity" name="item_${index + 1}_quantity" value="${item.quantity || ''}" step="any" required class="po-item-input">
                    </div>
                    <div class="form-group">
                      <label for="edit-item-${index + 1}-uom">UOM</label>
                      <input type="text" id="edit-item-${index + 1}-uom" name="item_${index + 1}_uom" value="${item.uom || ''}" required>
                    </div>
                    <div class="form-group">
                      <label for="edit-item-${index + 1}-unit-rate">Unit Rate</label>
                      <input type="number" id="edit-item-${index + 1}-unit-rate" name="item_${index + 1}_unit_rate" value="${item.unit_rate || ''}" step="any" required class="po-item-input">
                    </div>
                  </div>
                </fieldset>
              `).join('')}
            </div>
          </div>

          <!-- Budget Section -->
          <fieldset class="budget-fieldset form-group full-width">
            <legend>
              <i class="fas fa-calculator"></i>
              Allocation of Budget
            </legend>
            <div class="grid-4">
              <div class="form-group">
                <label>Indicative Price (₹)</label>
                <input id="edit-indicative-price" name="indicative_price" type="text" value="${po.basic_amount||''}" readonly>
              </div>
              <div class="form-group">
                <label>Department (from PR)</label>
                <input type="text" value="${pr.department||''}" readonly>
              </div>
              <div class="form-group">
                <label>Total Department Budget (₹)</label>
                <input id="edit-total-budget" name="budget_total" type="text" value="${budget.total_budget||''}" readonly>
              </div>
              <div class="form-group">
                <label>Remaining Budget (₹)</label>
                <input id="edit-remaining-budget" name="remaining_budget" type="text" value="${budget.remaining_budget||''}" readonly>
              </div>
            </div>
          </fieldset>

          <!-- Charges Section -->
          <fieldset class="charges-fieldset form-group full-width">
            <legend>
              <i class="fas fa-percentage"></i>
              Charges
            </legend>
            <div class="grid-4">
              <div class="form-group">
                <label>PF %</label>
                <input name="pf_rate" type="text" value="${po.pf_rate||'0'}">
              </div>
              <div class="form-group">
                <label>GST %</label>
                <input name="gst_rate" type="text" value="${po.gst_rate||'0'}">
              </div>
              <div class="form-group">
                <label>Freight %</label>
                <input name="freight_rate" type="text" value="${po.freight_rate||'0'}">
              </div>
              <div class="form-group">
                <label>Other %</label>
                <input name="other_rate" type="text" value="${po.other_rate||'0'}">
              </div>
            </div>
          </fieldset>

          <!-- NFA Section -->
          <fieldset id="edit-nfa-fieldset" class="form-group full-width" style="display:none;">
            <legend>
              <i class="fas fa-file-upload"></i>
              NFA (No Further Action) Document
            </legend>
            <div class="form-group">
              <label>Upload NFA Document</label>
              <input name="nfa_file" type="file" accept=".pdf,.doc,.docx">
            </div>
          </fieldset>

          <!-- Additional Documents Section -->
          <fieldset class="form-group full-width">
            <legend>
              <i class="fas fa-paperclip"></i>
              Additional Documents (Optional)
            </legend>
            <div class="grid-3">
              <div class="form-group">
                <label>Technical Specification - Approved MR Copy</label>
                <input name="tech_spec_file" type="file" accept=".pdf,.doc,.docx,.xls,.xlsx">
              </div>
              <div class="form-group">
                <label>Approved Price Comparative Sheet</label>
                <input name="price_comp_file" type="file" accept=".pdf,.doc,.docx,.xls,.xlsx">
              </div>
              <div class="form-group">
                <label>Approved NFA</label>
                <input name="nfa_doc_file" type="file" accept=".pdf,.doc,.docx">
              </div>
            </div>
          </fieldset>

          <!-- Submit Buttons -->
          <div class="form-group full-width" style="text-align: center; margin-top: var(--spacing-xl); padding-top: var(--spacing-lg); border-top: 2px solid var(--border-color);">
            <div style="display: flex; gap: var(--spacing-lg); justify-content: center; flex-wrap: wrap;">
              <button type="submit" class="btn-primary" style="padding: var(--spacing-md) var(--spacing-2xl); font-size: 1rem; min-width: 200px;">
                <i class="fas fa-save"></i>
                Update Purchase Order
              </button>
              <button type="button" class="btn-secondary" onclick="document.getElementById('edit-po-form-container').style.display='none'" style="padding: var(--spacing-md) var(--spacing-2xl); font-size: 1rem; min-width: 200px; background: var(--text-muted); color: white; border: none; border-radius: var(--radius-md); cursor: pointer; transition: all 0.2s ease;">
                <i class="fas fa-times"></i>
                Cancel
              </button>
            </div>
          </div>
        </form>
      `;

      // Items are already included in the form HTML above
      // Add event listeners for budget calculation
      setTimeout(() => {
        container.querySelectorAll('.po-item-input').forEach(input => {
          input.addEventListener('input', recalcBudgetPreview);
        });
      }, 0);

      // Budget frontend diff preview: fetch remaining based on PR project/department
      // Note: backend will adjust actual budgets; here we show indicative remaining after delta
      const basicOld = parseFloat((po.basic_amount||'0').toString().replace(/,/g,''))||0;
      const num = items.length; // Number of items
      function recalcBudgetPreview() {
        // Sum current item totals (qty*rate)
        let newBasic = 0;
        for (let i=1;i<=num;i++) {
          const q = parseFloat((document.querySelector(`#edit-item-${i}-quantity`)?.value||'0').replace(/,/g,''))||0;
          const r = parseFloat((document.querySelector(`#edit-item-${i}-unit-rate`)?.value||'0').replace(/,/g,''))||0;
          newBasic += q*r;
        }
        document.getElementById('edit-indicative-price').value = newBasic.toFixed(2);
        
        // Update remaining budget preview
        const totalBudget = parseFloat((budget.total_budget||'0').toString().replace(/,/g,''))||0;
        const difference = newBasic - basicOld; // Difference between current and previous indicative price
        const newRemaining = totalBudget - difference; // Remaining budget after accounting for the difference
        document.getElementById('edit-remaining-budget').value = newRemaining.toFixed(2);
        
        // Show/hide NFA fieldset based on budget or item type
        const nfaFieldset = document.getElementById('edit-nfa-fieldset');
        const isNonBudgeted = (pr.item_type||'').toLowerCase() === 'non-budgeted';
        const budgetExceeded = newRemaining < 0;
        
        if (isNonBudgeted || budgetExceeded) {
          nfaFieldset.style.display = 'block';
        } else {
          nfaFieldset.style.display = 'none';
        }
      }

      // Hook inputs for recalculation
      setTimeout(() => {
        for (let i=1;i<=num;i++) {
          ['quantity','unit-rate'].forEach(s => {
            const el = document.getElementById(`edit-item-${i}-${s}`);
            if (el) el.addEventListener('input', recalcBudgetPreview);
          });
        }
        // Initial calculation
        recalcBudgetPreview();
      }, 0);
    }
    
    // Note: populateEditPOItems() removed - items are now included directly in populateEditPOFormFull() HTML
    
    // Check Priority functionality
    const loadPriorityBtn = document.getElementById('load-priority-data');
    if (loadPriorityBtn) {
      loadPriorityBtn.addEventListener('click', function() {
        const priorityFilter = document.getElementById('priority-filter').value;
        loadPriorityData(priorityFilter);
      });
    }
    
    // Load priority data based on filters
    function loadPriorityData(priorityFilter) {
      const resultsContainer = document.getElementById('priority-results');
      if (!resultsContainer) return;
      
      resultsContainer.innerHTML = '<div class="text-center py-4"><div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div><p class="text-gray-600">Loading priority data...</p></div>';
      
      fetch('/api/get_priority_data', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ priority_filter: priorityFilter })
      })
      .then(response => response.json())
      .then(data => {
        if (data.success && data.purchase_requisitions) {
          displayPriorityResults(data.purchase_requisitions);
        } else {
          resultsContainer.innerHTML = `<div class="text-center py-4 text-red-600">Error: ${data.message || 'Failed to load priority data'}</div>`;
        }
      })
      .catch(error => {
        console.error('Error loading priority data:', error);
        resultsContainer.innerHTML = '<div class="text-center py-4 text-red-600">Error loading priority data</div>';
      });
    }
    
    // Display priority results
    function displayPriorityResults(prs) {
      const resultsContainer = document.getElementById('priority-results');
      if (!resultsContainer) return;
      
      if (prs.length === 0) {
        resultsContainer.innerHTML = '<div class="text-center py-8 text-gray-600">No purchase requisitions found matching the criteria.</div>';
        return;
      }
      
      // Sort by nearest Expected Delivery Date within the selected priority
      prs.sort((a, b) => {
        const da = a.expected_delivery_date ? new Date(a.expected_delivery_date) : new Date(8640000000000000);
        const db = b.expected_delivery_date ? new Date(b.expected_delivery_date) : new Date(8640000000000000);
        return da - db;
      });
      
      let html = '<div class="space-y-4">';
      html += '<h3 class="text-lg font-semibold text-gray-800 mb-4">Priority Purchase Requisitions</h3>';
      
      prs.forEach((pr, index) => {
        const priorityColor = pr.priority === 'Critical' ? 'red' : 'yellow';
        const edd = pr.expected_delivery_date || '-';
        const today = new Date();
        const dueDate = pr.expected_delivery_date ? new Date(pr.expected_delivery_date) : null;
        const daysLeft = dueDate ? Math.ceil((dueDate - today) / (1000*60*60*24)) : null;
        
        // Calculate Days Elapsed (from PR creation date to today)
        const prDate = pr.date ? new Date(pr.date) : null;
        const daysElapsed = prDate ? Math.floor((today - prDate) / (1000*60*60*24)) : null;
        
        const urgencyColor = daysLeft !== null ? (daysLeft < 0 ? 'red' : daysLeft <= 7 ? 'orange' : 'green') : 'gray';
        const urgencyText = daysLeft !== null ? (daysLeft < 0 ? 'Overdue' : daysLeft <= 7 ? 'Soon' : 'Normal') : 'Unknown';
        
        html += `
          <div class="border border-gray-200 rounded-lg p-4 bg-white shadow-sm hover:shadow-md transition-shadow">
            <div class="flex items-center justify-between mb-3">
              <div class="flex items-center space-x-3">
                <span class="px-3 py-1 rounded-full text-sm font-medium bg-${priorityColor}-100 text-${priorityColor}-800">
                  ${pr.priority}
                </span>
                <span class="px-3 py-1 rounded-full text-sm font-medium bg-${urgencyColor}-100 text-${urgencyColor}-800">
                  ${urgencyText}
                </span>
                <span class="text-sm text-gray-600">#${index + 1} Priority</span>
              </div>
              <div class="text-right">
                <div class="text-sm text-gray-600">Expected Delivery</div>
                <div class="text-lg font-semibold text-${urgencyColor}-600">${edd}${daysLeft !== null ? ` (${daysLeft} days)` : ''}</div>
              </div>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
              <div>
                <div class="text-sm text-gray-600">PR Number</div>
                <div class="font-medium">${pr.pr_number}</div>
              </div>
              <div>
                <div class="text-sm text-gray-600">Project</div>
                <div class="font-medium">${pr.project_name}</div>
              </div>
              <div>
                <div class="text-sm text-gray-600">Department</div>
                <div class="font-medium">${pr.department}</div>
              </div>
              <div>
                <div class="text-sm text-gray-600">Requester</div>
                <div class="font-medium">${pr.requester_name}</div>
              </div>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <div class="text-sm text-gray-600">Expected Delivery Date</div>
                <div class="font-medium">${pr.expected_delivery_date || '-'}</div>
              </div>
              <div>
                <div class="text-sm text-gray-600">Days Elapsed</div>
                <div class="font-medium ${daysElapsed !== null ? (daysElapsed > 30 ? 'text-red-600' : daysElapsed > 14 ? 'text-orange-600' : 'text-green-600') : 'text-gray-500'}">${daysElapsed !== null ? daysElapsed + ' days' : '-'}</div>
              </div>
              <div>
                <div class="text-sm text-gray-600">Days Remaining</div>
                <div class="font-medium ${daysLeft !== null && (daysLeft < 0 ? 'text-red-600' : daysLeft < 5 ? 'text-orange-600' : 'text-green-600')}">${daysLeft !== null ? daysLeft + ' days' : '-'}</div>
              </div>
            </div>
            
          </div>
        `;
      });
      
      html += '</div>';
      resultsContainer.innerHTML = html;
    }
  }

// ─── PR/PO Status Tab & Lookup ─────────────────────────────
  const statusModal = document.getElementById('modal-status');
  if (statusModal) {
    const tabPr = document.getElementById('tab-status-pr');
    const tabPo = document.getElementById('tab-status-po');
    const sectPr = document.getElementById('status-pr-section');
    const sectPo = document.getElementById('status-po-section');
    const btnCheck = document.getElementById('check-status');
    const resPr = document.getElementById('status-pr-result');
    const resPo = document.getElementById('status-po-result');
    const inpPr = document.getElementById('status-pr-number');
    const inpPo = document.getElementById('status-po-number');
    const slider = statusModal.querySelector('.status-slider');

    function activatePR() {
      tabPr.classList.add('active');
      tabPo.classList.remove('active');
      if (slider) slider.style.transform = 'translateX(0)';
      sectPr.style.display = 'block';
      sectPo.style.display = 'none';
      resPr.innerHTML = '';
      resPo.innerHTML = '';
    }

    function activatePO() {
      tabPo.classList.add('active');
      tabPr.classList.remove('active');
      if (slider) slider.style.transform = 'translateX(100%)';
      sectPo.style.display = 'block';
      sectPr.style.display = 'none';
      resPo.innerHTML = '';
      resPr.innerHTML = '';
    }

    tabPr.addEventListener('click', activatePR);
    tabPo.addEventListener('click', activatePO);

    btnCheck.addEventListener('click', () => {
      if (sectPr.style.display !== 'none') {
        const pr = inpPr.value.trim();
        if (!pr) return alert('Please enter a PR number.');
        fetch(`/status_pr?pr=${encodeURIComponent(pr)}`)
          .then(r => r.json())
          .then(json => { resPr.innerHTML = `<div class="PO-display">${json.message}</div>`; })
          .catch(() => { resPr.innerHTML = `<div class="PO-display error">Error checking PR status.</div>`; });
      } else {
        const po = inpPo.value.trim();
        if (!po) return alert('Please enter a PO number.');
        fetch(`/status_po?po=${encodeURIComponent(po)}`)
          .then(r => r.json())
          .then(json => {
            let msg = `<div class="PO-display">${json.message}</div>`;
            if (json.download_url) {
              msg += `<div style="margin-top:0.5rem; text-align:center;">
                          <a href="${json.download_url}" class="btn-primary" style="text-decoration:none; display:inline-block; padding: 0.5rem 1rem; margin-right: 0.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-weight: 500; transition: all 0.3s ease;">
                            <i class="fas fa-download" style="margin-right: 0.25rem;"></i>Download PO
                          </a>`;
              
              // Add additional documents download button if available
              if (json.additional_docs_url) {
                msg += `<a href="${json.additional_docs_url}" class="btn-secondary" style="text-decoration:none; display:inline-block; padding: 0.5rem 1rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-weight: 500; transition: all 0.3s ease;">
                          <i class="fas fa-file-archive" style="margin-right: 0.25rem;"></i>Download Additional Documents
                        </a>`;
              }
              
              msg += `</div>`;
            }
            resPo.innerHTML = msg;
          })
          .catch(() => { resPo.innerHTML = `<div class="PO-display error">Error checking PO status.</div>`; });
      }
    });

    // Initialize on PR tab when the modal is opened
    document.querySelector('[data-modal="modal-status"]').addEventListener('click', activatePR);
  }

// ─── Live Notifications Polling & Toggle ────────────────────────────────
(function() {
  const btn = document.getElementById('notificationBtn');
  const dd  = document.getElementById('notificationDropdown');
  const cnt = document.getElementById('notifCount');
  const list= document.getElementById('notificationsList');

  // Mobile notification elements
  const mobileBtn = document.getElementById('mobileNotificationBtn');
  const mobileList = document.getElementById('mobileNotificationList');
  const mobileCnt = document.getElementById('mobileNotifCount');
  const mobileNotesList = document.getElementById('mobileNotificationsList');

  if (!btn && !mobileBtn) return;  // only on PO screen

  // fetch from server and render
  function fetchNotifications() {
    fetch('/notifications', {
      headers: {
        'X-Requested-With': 'XMLHttpRequest'
      }
    })
      .then(r => {
        if (r.status === 401) {
          console.log('Authentication required for notifications');
          return Promise.reject(new Error('Authentication required'));
        }
        return r.json();
      })
      .then(data => {
        const notes = data.notifications || [];
        
        // Update desktop notifications
        if (cnt) cnt.textContent = notes.length;
        if (mobileCnt) mobileCnt.textContent = notes.length;
        
        // Update desktop list
        if (list) {
        list.innerHTML = '';
          if (notes.length === 0) {
            list.innerHTML = `
              <li class="p-4 text-center text-slate-500">
                <i class="fas fa-bell-slash text-2xl mb-2 block"></i>
                <span class="text-sm">No notifications yet!</span>
              </li>
            `;
          } else {
            notes.forEach((n, index) => {
          const li = document.createElement('li');
              li.className = 'p-3 hover:bg-slate-50 transition-colors duration-200 border-b border-slate-100 last:border-b-0';
              li.innerHTML = `
                <div class="flex items-start space-x-3">
                  <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center flex-shrink-0">
                    <i class="${n.icon} text-white text-xs"></i>
                  </div>
                  <div class="flex-1 min-w-0">
                    <p class="text-sm text-slate-700 leading-relaxed">${n.text}</p>
                    <p class="text-xs text-slate-500 mt-1">#${n.ref}</p>
                  </div>
                </div>
              `;
          list.appendChild(li);
        });
          }
        }
        
        // Update mobile list
        if (mobileNotesList) {
          mobileNotesList.innerHTML = '';
          if (notes.length === 0) {
            mobileNotesList.innerHTML = `
              <li class="p-3 text-center text-slate-500 bg-slate-50 rounded-lg">
                <i class="fas fa-bell-slash text-xl mb-2 block"></i>
                <span class="text-sm">No notifications yet!</span>
              </li>
            `;
          } else {
            notes.forEach((n, index) => {
              const li = document.createElement('li');
              li.className = 'p-3 bg-slate-50 rounded-lg border border-slate-200';
              li.innerHTML = `
                <div class="flex items-start space-x-3">
                  <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center flex-shrink-0">
                    <i class="${n.icon} text-white text-xs"></i>
                  </div>
                  <div class="flex-1 min-w-0">
                    <p class="text-sm text-slate-700 leading-relaxed">${n.text}</p>
                    <p class="text-xs text-slate-500 mt-1">#${n.ref}</p>
                  </div>
                </div>
              `;
              mobileNotesList.appendChild(li);
            });
          }
        }
      })
      .catch(console.error);
  }

    // Desktop notification handlers
    if (btn && dd) {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            // Toggle visibility using Tailwind classes
            if (dd.classList.contains('opacity-0')) {
                dd.classList.remove('opacity-0', 'invisible', 'translate-y-2');
                dd.classList.add('opacity-100', 'visible', 'translate-y-0');
            } else {
                dd.classList.add('opacity-0', 'invisible', 'translate-y-2');
                dd.classList.remove('opacity-100', 'visible', 'translate-y-0');
            }
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!btn.contains(e.target) && !dd.contains(e.target)) {
                dd.classList.add('opacity-0', 'invisible', 'translate-y-2');
                dd.classList.remove('opacity-100', 'visible', 'translate-y-0');
            }
        });
    }

    // Mobile notification handlers
    if (mobileBtn && mobileList) {
        mobileBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            mobileList.classList.toggle('hidden');
        });
    }

  // initial + poll every 15s
  fetchNotifications();
  setInterval(fetchNotifications, 15000);
})();

async function renderPOCharts() {
  try {
    console.log('Starting renderPOCharts with Chart.js...');
    
    // Check if Chart.js is available
    if (typeof Chart === 'undefined' || !Chart) {
      console.log('Chart.js not available, using fallback charts');
      await renderSimpleCharts();
      return;
    }
    
    // Destroy existing charts if they exist
    const chartContainers = ['chartPoCount', 'chartSpendTrend', 'chartTopVendors', 'chartAvgPoValue'];
    chartContainers.forEach(id => {
      const container = document.getElementById(id);
      if (container) {
        // Clear existing content
        container.innerHTML = '<canvas></canvas>';
      }
    });

    // Ultra-modern chart configuration
    const chartConfig = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: {
            usePointStyle: true,
            padding: 24,
            font: {
              size: 13,
              weight: '600',
              family: 'Inter, sans-serif'
            },
            color: '#374151',
            generateLabels: function(chart) {
              const datasets = chart.data.datasets;
              return datasets.map((dataset, i) => ({
                text: dataset.label,
                fillStyle: dataset.backgroundColor || dataset.borderColor,
                strokeStyle: dataset.borderColor,
                lineWidth: 2,
                pointStyle: 'circle',
                hidden: !chart.isDatasetVisible(i),
                index: i
              }));
            }
          }
        },
        tooltip: {
          backgroundColor: 'rgba(17, 24, 39, 0.95)',
          titleColor: '#ffffff',
          bodyColor: '#ffffff',
          borderColor: '#3b82f6',
          borderWidth: 2,
          cornerRadius: 12,
          displayColors: true,
          padding: 16,
          titleFont: {
            size: 15,
            weight: '700',
            family: 'Inter, sans-serif'
          },
          bodyFont: {
            size: 14,
            weight: '500',
            family: 'Inter, sans-serif'
          },
          boxPadding: 8,
          usePointStyle: true,
          callbacks: {
            title: function(context) {
              return context[0].label;
            }
          }
        }
      },
      elements: {
        point: {
          radius: 6,
          hoverRadius: 8,
          borderWidth: 3,
          hoverBorderWidth: 4,
          backgroundColor: '#ffffff'
        },
        line: {
          tension: 0.5,
          borderWidth: 4,
          fill: true
        },
        bar: {
          borderRadius: 8,
          borderSkipped: false
        }
      },
      interaction: {
        intersect: false,
        mode: 'index'
      },
      animation: {
        duration: 1500,
        easing: 'easeInOutQuart'
      },
      layout: {
        padding: {
          top: 20,
          right: 20,
          bottom: 20,
          left: 20
        }
      }
    };

    // 1) Monthly PO Count - Modern Line Chart
    let res = await fetch('/api/monthly_po_count');
    let json = await res.json();
    if (json.labels && json.labels.length > 0) {
      const ctx = document.getElementById('chartPoCount').querySelector('canvas').getContext('2d');
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: json.labels,
          datasets: [{
            label: 'Purchase Orders',
            data: json.data,
            borderColor: '#6366f1',
            backgroundColor: 'rgba(99, 102, 241, 0.15)',
            borderWidth: 4,
            fill: true,
            tension: 0.5,
            pointBackgroundColor: '#ffffff',
            pointBorderColor: '#6366f1',
            pointBorderWidth: 3,
            pointRadius: 6,
            pointHoverRadius: 8,
            pointHoverBorderWidth: 4
          }]
        },
        options: {
          ...chartConfig,
          plugins: {
            ...chartConfig.plugins,
            title: {
              display: true,
              text: 'Monthly Purchase Order Count',
              font: {
                size: 16,
                weight: '600'
              },
              color: '#1e293b',
              padding: 20
            }
          },
          scales: {
            x: {
              grid: {
                display: false
              },
              ticks: {
                font: {
                  size: 12
                },
                color: '#64748b'
              }
            },
            y: {
              beginAtZero: true,
              grid: {
                color: 'rgba(100, 116, 139, 0.1)'
              },
              ticks: {
                stepSize: 1,
                font: {
                  size: 12
                },
                color: '#64748b'
              }
            }
          }
        }
      });
    } else {
      document.getElementById('chartPoCount').innerHTML = '<div class="no-data-message"><i class="fas fa-chart-line"></i><p>No data available</p></div>';
    }

    // 2) Monthly Spend Trend - Modern Line Chart
    res = await fetch('/api/monthly_spend_trend');
    json = await res.json();
    if (json.labels && json.labels.length > 0) {
      const ctx = document.getElementById('chartSpendTrend').querySelector('canvas').getContext('2d');
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: json.labels,
          datasets: [{
            label: 'Total Spend',
            data: json.data,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.15)',
            borderWidth: 4,
            fill: true,
            tension: 0.5,
            pointBackgroundColor: '#ffffff',
            pointBorderColor: '#10b981',
            pointBorderWidth: 3,
            pointRadius: 6,
            pointHoverRadius: 8,
            pointHoverBorderWidth: 4
          }]
        },
        options: {
          ...chartConfig,
          plugins: {
            ...chartConfig.plugins,
            title: {
              display: true,
              text: 'Monthly Spend Trend',
              font: {
                size: 16,
                weight: '600'
              },
              color: '#1e293b',
              padding: 20
            },
            tooltip: {
              ...chartConfig.plugins.tooltip,
              callbacks: {
                label: function(context) {
                  return 'Spend: ₹' + context.parsed.y.toLocaleString();
                }
              }
            }
          },
          scales: {
            x: {
              grid: {
                display: false
              },
              ticks: {
                font: {
                  size: 12
                },
                color: '#64748b'
              }
            },
            y: {
              beginAtZero: true,
              grid: {
                color: 'rgba(100, 116, 139, 0.1)'
              },
              ticks: {
                font: {
                  size: 12
                },
                color: '#64748b',
                callback: function(value) {
                  return '₹' + value.toLocaleString();
                }
              }
            }
          }
        }
      });
    } else {
      document.getElementById('chartSpendTrend').innerHTML = '<div class="no-data-message"><i class="fas fa-chart-line"></i><p>No data available</p></div>';
    }

    // 3) Top 5 Vendors by Spend - Modern Bar Chart
    res = await fetch('/api/top_vendors_by_spend', {
      headers: {
        'X-Requested-With': 'XMLHttpRequest'
      }
    });
    if (res.status === 401) {
      console.log('Authentication required for top vendors by spend');
      return;
    }
    json = await res.json();
    if (json.labels && json.labels.length > 0) {
      const ctx = document.getElementById('chartTopVendors').querySelector('canvas').getContext('2d');
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: json.labels,
          datasets: [{
            label: 'Total Spend',
            data: json.data,
            backgroundColor: [
              'rgba(99, 102, 241, 0.9)',
              'rgba(139, 92, 246, 0.9)',
              'rgba(236, 72, 153, 0.9)',
              'rgba(245, 158, 11, 0.9)',
              'rgba(34, 197, 94, 0.9)'
            ],
            borderColor: [
              '#6366f1',
              '#8b5cf6',
              '#ec4899',
              '#f59e0b',
              '#22c55e'
            ],
            borderWidth: 3,
            borderRadius: 10,
            borderSkipped: false,
            hoverBackgroundColor: [
              'rgba(99, 102, 241, 1)',
              'rgba(139, 92, 246, 1)',
              'rgba(236, 72, 153, 1)',
              'rgba(245, 158, 11, 1)',
              'rgba(34, 197, 94, 1)'
            ],
            hoverBorderColor: [
              '#4f46e5',
              '#7c3aed',
              '#db2777',
              '#d97706',
              '#16a34a'
            ],
            hoverBorderWidth: 4
          }]
        },
        options: {
          ...chartConfig,
          plugins: {
            ...chartConfig.plugins,
            title: {
              display: true,
              text: 'Top 5 Vendors by Spend',
              font: {
                size: 16,
                weight: '600'
              },
              color: '#1e293b',
              padding: 20
            },
            tooltip: {
              ...chartConfig.plugins.tooltip,
              callbacks: {
                label: function(context) {
                  return 'Spend: ₹' + context.parsed.y.toLocaleString();
                }
              }
            }
          },
          scales: {
            x: {
              grid: {
                display: false
              },
              ticks: {
                font: {
                  size: 11
                },
                color: '#64748b',
                maxRotation: 45
              }
            },
            y: {
              beginAtZero: true,
              grid: {
                color: 'rgba(100, 116, 139, 0.1)'
              },
              ticks: {
                font: {
                  size: 12
                },
                color: '#64748b',
                callback: function(value) {
                  return '₹' + value.toLocaleString();
                }
              }
            }
          }
        }
      });
    } else {
      document.getElementById('chartTopVendors').innerHTML = '<div class="no-data-message"><i class="fas fa-chart-bar"></i><p>No data available</p></div>';
    }

    // 4) Average PO Value by Month - Modern Bar Chart
    res = await fetch('/api/avg_po_value_by_month');
    json = await res.json();
    if (json.labels && json.labels.length > 0) {
      const ctx = document.getElementById('chartAvgPoValue').querySelector('canvas').getContext('2d');
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: json.labels,
          datasets: [{
            label: 'Average Value',
            data: json.data,
            backgroundColor: 'rgba(14, 165, 233, 0.9)',
            borderColor: '#0ea5e9',
            borderWidth: 3,
            borderRadius: 10,
            borderSkipped: false,
            hoverBackgroundColor: 'rgba(14, 165, 233, 1)',
            hoverBorderColor: '#0284c7',
            hoverBorderWidth: 4
          }]
        },
        options: {
          ...chartConfig,
          plugins: {
            ...chartConfig.plugins,
            title: {
              display: true,
              text: 'Average PO Value by Month',
              font: {
                size: 16,
                weight: '600'
              },
              color: '#1e293b',
              padding: 20
            },
            tooltip: {
              ...chartConfig.plugins.tooltip,
              callbacks: {
                label: function(context) {
                  return 'Average: ₹' + context.parsed.y.toLocaleString();
                }
              }
            }
          },
          scales: {
            x: {
              grid: {
                display: false
              },
              ticks: {
                font: {
                  size: 12
                },
                color: '#64748b'
              }
            },
            y: {
              beginAtZero: true,
              grid: {
                color: 'rgba(100, 116, 139, 0.1)'
              },
              ticks: {
                font: {
                  size: 12
                },
                color: '#64748b',
                callback: function(value) {
                  return '₹' + value.toLocaleString();
                }
              }
            }
          }
        }
      });
    } else {
      document.getElementById('chartAvgPoValue').innerHTML = '<div class="no-data-message"><i class="fas fa-chart-bar"></i><p>No data available</p></div>';
    }
  } catch (error) {
    console.error('Error rendering charts:', error);
    console.log('Attempting fallback to simple charts...');
    
    // Try to show simple text-based charts as fallback
    try {
      await renderSimpleCharts();
    } catch (fallbackError) {
      console.error('Fallback charts also failed:', fallbackError);
      // Show error message in chart containers
      const chartContainers = ['chartPoCount', 'chartSpendTrend', 'chartTopVendors', 'chartAvgPoValue'];
      chartContainers.forEach(id => {
        const container = document.getElementById(id);
        if (container) {
          container.innerHTML = '<div class="no-data-message error"><i class="fas fa-exclamation-triangle"></i><p>Error loading chart data</p></div>';
        }
      });
    }
  }
}

// Simple fallback charts using HTML/CSS
async function renderSimpleCharts() {
  const chartContainers = ['chartPoCount', 'chartSpendTrend', 'chartTopVendors', 'chartAvgPoValue'];

  // 1) Monthly PO Count
  let res = await fetch('/api/monthly_po_count', {
    headers: {
      'X-Requested-With': 'XMLHttpRequest'
    }
  });
  if (res.status === 401) {
    console.log('Authentication required for monthly PO count');
    return;
  }
  let json = await res.json();
  if (json.labels && json.labels.length > 0) {
    const container = document.getElementById('chartPoCount');
    if (container) {
      let html = '<div style="padding: 20px;"><h4>Monthly PO Count</h4><div style="display: flex; align-items: end; height: 200px; gap: 10px;">';
      const maxValue = Math.max(...json.data);
      json.labels.forEach((label, index) => {
        const height = (json.data[index] / maxValue) * 150;
        html += `<div style="flex: 1; display: flex; flex-direction: column; align-items: center;"><div style="background: #8884d8; width: 30px; height: ${height}px; margin-bottom: 10px;"></div><div style="font-size: 12px; text-align: center;">${label}</div><div style="font-size: 10px; color: #666;">${json.data[index]}</div></div>`;
      });
      html += '</div></div>';
      container.innerHTML = html;
    }
  }

  // 2) Monthly Spend Trend
  res = await fetch('/api/monthly_spend_trend', {
    headers: {
      'X-Requested-With': 'XMLHttpRequest'
    }
  });
  if (res.status === 401) {
    console.log('Authentication required for monthly spend trend');
    return;
  }
  json = await res.json();
  if (json.labels && json.labels.length > 0) {
    const container = document.getElementById('chartSpendTrend');
    if (container) {
      let html = '<div style="padding: 20px;"><h4>Monthly Spend Trend</h4><div style="display: flex; align-items: end; height: 200px; gap: 10px;">';
      const maxValue = Math.max(...json.data);
      json.labels.forEach((label, index) => {
        const height = (json.data[index] / maxValue) * 150;
        html += `<div style="flex: 1; display: flex; flex-direction: column; align-items: center;"><div style="background: #82ca9d; width: 30px; height: ${height}px; margin-bottom: 10px;"></div><div style="font-size: 12px; text-align: center;">${label}</div><div style="font-size: 10px; color: #666;">₹${json.data[index].toLocaleString()}</div></div>`;
      });
      html += '</div></div>';
      container.innerHTML = html;
    }
  }

  // 3) Top 5 Vendors by Spend
  res = await fetch('/api/top_vendors_by_spend', {
    headers: {
      'X-Requested-With': 'XMLHttpRequest'
    }
  });
  if (res.status === 401) {
    console.log('Authentication required for top vendors by spend');
    return;
  }
  json = await res.json();
  if (json.labels && json.labels.length > 0) {
    const container = document.getElementById('chartTopVendors');
    if (container) {
      let html = '<div style="padding: 20px;"><h4>Top 5 Vendors by Spend</h4><div style="display: flex; align-items: end; height: 200px; gap: 10px;">';
      const maxValue = Math.max(...json.data);
      json.labels.forEach((label, index) => {
        const height = (json.data[index] / maxValue) * 150;
        html += `<div style="flex: 1; display: flex; flex-direction: column; align-items: center;"><div style="background: #8884d8; width: 30px; height: ${height}px; margin-bottom: 10px;"></div><div style="font-size: 12px; text-align: center;">${label}</div><div style="font-size: 10px; color: #666;">₹${json.data[index].toLocaleString()}</div></div>`;
      });
      html += '</div></div>';
      container.innerHTML = html;
    }
  }

  // 4) Average PO Value by Month
  res = await fetch('/api/avg_po_value_by_month', {
    headers: {
      'X-Requested-With': 'XMLHttpRequest'
    }
  });
  if (res.status === 401) {
    console.log('Authentication required for average PO value by month');
    return;
  }
  json = await res.json();
  if (json.labels && json.labels.length > 0) {
    const container = document.getElementById('chartAvgPoValue');
    if (container) {
      let html = '<div style="padding: 20px;"><h4>Average PO Value by Month</h4><div style="display: flex; align-items: end; height: 200px; gap: 10px;">';
      const maxValue = Math.max(...json.data);
      json.labels.forEach((label, index) => {
        const height = (json.data[index] / maxValue) * 150;
        html += `<div style="flex: 1; display: flex; flex-direction: column; align-items: center;"><div style="background: #82ca9d; width: 30px; height: ${height}px; margin-bottom: 10px;"></div><div style="font-size: 12px; text-align: center;">${label}</div><div style="font-size: 10px; color: #666;">₹${json.data[index].toLocaleString()}</div></div>`;
      });
      html += '</div></div>';
      container.innerHTML = html;
    }
  }
}

// ── Real-time Dashboard Stats ─────────────────────────────
function fetchDashboardStats() {
    fetch('/api/dashboard_stats', {
      headers: {
        'X-Requested-With': 'XMLHttpRequest'
      }
    })
      .then(r => {
        if (r.status === 401) {
          console.log('Authentication required for dashboard stats');
          return Promise.reject(new Error('Authentication required'));
        }
        return r.json();
      })
      .then(stats => {
        document.getElementById('total-pos').textContent = stats.total_pos;
        document.getElementById('pending-approvals').textContent = stats.pending_approvals;
        document.getElementById('completed-pos').textContent = stats.completed;
        document.getElementById('total-value').textContent = stats.total_value;
      })
      .catch(console.error);
  }

// Function to refresh all dashboard components
function refreshDashboard() {
    console.log('Refreshing dashboard...');
    fetchDashboardStats();
    if (typeof renderPOCharts === 'function') {
        renderPOCharts();
    }
    console.log('Dashboard refreshed');
}

// Function to initialize dashboard with existing data
function initializeDashboard() {
    console.log('Initializing dashboard...');
    
    // Immediately fetch and display existing data
    fetchDashboardStats();
    
    // Initialize charts if they exist
    if (typeof renderPOCharts === 'function') {
        setTimeout(() => {
            renderPOCharts();
            console.log('Charts initialized with existing data');
        }, 500);
    }
    
    // Set up periodic refresh
    setInterval(fetchDashboardStats, 15000); // Poll every 15 seconds
}

 if (document.getElementById('total-pos')) {
        initializeDashboard(); // Initial fetch
    }

// Initialize charts when DOM is ready and libraries are loaded
function initializeCharts() {
  if (document.getElementById('chartPoCount')) {
    // Check if Chart.js is loaded
    if (typeof Chart !== 'undefined' && Chart) {
      console.log('Chart.js loaded, initializing charts...');
        renderPOCharts();
    } else {
      console.log('Waiting for Chart.js to load...');
      // Retry after a short delay
      setTimeout(initializeCharts, 500);
    }
  }
}

// Wait for both DOM and window load events
function startChartInitialization() {
  if (document.readyState === 'complete') {
    // Page is fully loaded, start initialization
    setTimeout(initializeCharts, 500);
  } else {
    // Wait for window load event
    window.addEventListener('load', () => {
      setTimeout(initializeCharts, 500);
    });
  }
}

// ─── Additional Documents Functionality ────────────────────────────────
(function() {
  // Store additional documents data
  let additionalDocsData = {
    tech_spec_file: null,
    price_comp_file: null,
    nfa_doc_file: null
  };

  // Additional Documents button click handler
  const additionalDocsBtn = document.getElementById('additional-docs-btn');
  if (additionalDocsBtn) {
    additionalDocsBtn.addEventListener('click', function() {
      openModal('modal-additional-docs');
    });
  }

  // File input change handlers
  const techSpecFile = document.getElementById('tech-spec-file');
  const priceCompFile = document.getElementById('price-comp-file');
  const nfaDocFile = document.getElementById('nfa-doc-file');

  if (techSpecFile) {
    techSpecFile.addEventListener('change', function(e) {
      additionalDocsData.tech_spec_file = e.target.files[0] || null;
      updateFileDisplay('tech-spec-file', e.target.files[0]);
    });
  }

  if (priceCompFile) {
    priceCompFile.addEventListener('change', function(e) {
      additionalDocsData.price_comp_file = e.target.files[0] || null;
      updateFileDisplay('price-comp-file', e.target.files[0]);
    });
  }

  if (nfaDocFile) {
    nfaDocFile.addEventListener('change', function(e) {
      additionalDocsData.nfa_doc_file = e.target.files[0] || null;
      updateFileDisplay('nfa-doc-file', e.target.files[0]);
    });
  }

  // Update file display
  function updateFileDisplay(inputId, file) {
    const input = document.getElementById(inputId);
    if (file) {
      // Add a small indicator that file is selected
      const existingIndicator = input.parentNode.querySelector('.file-selected-indicator');
      if (existingIndicator) {
        existingIndicator.remove();
      }
      
      const indicator = document.createElement('div');
      indicator.className = 'file-selected-indicator';
      indicator.style.cssText = 'color: #10b981; font-size: 0.75rem; margin-top: 0.25rem; font-weight: 500;';
      indicator.innerHTML = `✓ ${file.name}`;
      input.parentNode.appendChild(indicator);
    } else {
      const existingIndicator = input.parentNode.querySelector('.file-selected-indicator');
      if (existingIndicator) {
        existingIndicator.remove();
      }
    }
  }

  // Save additional documents
  const saveAdditionalDocsBtn = document.getElementById('save-additional-docs');
  if (saveAdditionalDocsBtn) {
    saveAdditionalDocsBtn.addEventListener('click', function() {
      // Check if at least one file is selected
      const hasFiles = additionalDocsData.tech_spec_file || 
                      additionalDocsData.price_comp_file || 
                      additionalDocsData.nfa_doc_file;
      
      if (!hasFiles) {
        alert('Please select at least one document to upload.');
        return;
      }

      // Update the button text to show files are saved
      const additionalDocsBtn = document.getElementById('additional-docs-btn');
      if (additionalDocsBtn) {
        const fileCount = [additionalDocsData.tech_spec_file, additionalDocsData.price_comp_file, additionalDocsData.nfa_doc_file].filter(f => f).length;
        additionalDocsBtn.innerHTML = `<i class="fas fa-check" style="margin-right: 8px;"></i>${fileCount} Document(s) Selected`;
        additionalDocsBtn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
      }

      // Close the modal
      closeModal('modal-additional-docs');
      
      // Show success message
      alert('Additional documents have been selected. They will be uploaded when you generate the PO.');
    });
  }

  // Make additionalDocsData available globally for form submission
  window.additionalDocsData = additionalDocsData;

  // Handle PO form submission to include additional documents
  const poForm = document.querySelector('form[action*="generate_form"]');
  if (poForm) {
    poForm.addEventListener('submit', function(e) {
      // Create FormData to handle file uploads
      const formData = new FormData(poForm);
      
      // Add additional documents to the form data
      if (additionalDocsData.tech_spec_file) {
        formData.append('tech_spec_file', additionalDocsData.tech_spec_file);
      }
      if (additionalDocsData.price_comp_file) {
        formData.append('price_comp_file', additionalDocsData.price_comp_file);
      }
      if (additionalDocsData.nfa_doc_file) {
        formData.append('nfa_doc_file', additionalDocsData.nfa_doc_file);
      }
      
      // Prevent default form submission
      e.preventDefault();
      
      // Show loading state
      const submitBtn = poForm.querySelector('button[type="submit"]');
      const originalText = submitBtn.textContent;
      submitBtn.textContent = 'Generating PO...';
      submitBtn.disabled = true;
      
      // Submit the form with additional documents
      fetch(poForm.action, {
        method: 'POST',
        body: formData
      })
      .then(response => {
        if (response.ok) {
          // Redirect to the response URL or show success message
          window.location.href = response.url;
        } else {
          throw new Error('Failed to generate PO');
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('Error generating PO. Please try again.');
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
      });
    });
  }
})();

// Start the process
startChartInitialization();

// ─── Special Conditions of Contract Dynamic Fields ─────────────────────────────

// Payment Milestones Management
let paymentMilestoneCount = 1;
let deliveryScheduleCount = 1;

// Add Payment Milestone
function addPaymentMilestone() {
  console.log('addPaymentMilestone called, current count:', paymentMilestoneCount);
  paymentMilestoneCount++;
  const container = document.getElementById('payment_milestones_container');
  if (!container) {
    console.error('Payment milestones container not found');
    return;
  }
  const newItem = document.createElement('div');
  newItem.className = 'payment-milestone-item';
  newItem.innerHTML = `
    <input type="text" name="payment_milestone_${paymentMilestoneCount}" placeholder="Payment Milestone ${paymentMilestoneCount}" class="milestone-input">
    <button type="button" class="remove-milestone-btn" onclick="removePaymentMilestone(this)">Remove</button>
  `;
  container.appendChild(newItem);
  
  // Show remove buttons for all items if more than 1
  if (paymentMilestoneCount > 1) {
    document.querySelectorAll('.remove-milestone-btn').forEach(btn => {
      btn.style.display = 'inline-block';
    });
  }
  console.log('Payment milestone added, new count:', paymentMilestoneCount);
}

// Make functions globally accessible
window.addPaymentMilestone = addPaymentMilestone;

// Remove Payment Milestone
function removePaymentMilestone(button) {
  console.log('removePaymentMilestone called');
  const container = document.getElementById('payment_milestones_container');
  if (container.children.length > 1) {
    button.parentElement.remove();
    paymentMilestoneCount--;
    
    // Hide remove buttons if only 1 item left
    if (paymentMilestoneCount === 1) {
      document.querySelectorAll('.remove-milestone-btn').forEach(btn => {
        btn.style.display = 'none';
      });
    }
  }
}

// Make functions globally accessible
window.removePaymentMilestone = removePaymentMilestone;

// Add Delivery Schedule
function addDeliverySchedule() {
  console.log('addDeliverySchedule called, current count:', deliveryScheduleCount);
  deliveryScheduleCount++;
  const container = document.getElementById('delivery_schedule_container');
  if (!container) {
    console.error('Delivery schedule container not found');
    return;
  }
  const newItem = document.createElement('div');
  newItem.className = 'delivery-schedule-item';
  newItem.innerHTML = `
    <input type="text" name="delivery_schedule_${deliveryScheduleCount}" placeholder="Delivery Schedule ${deliveryScheduleCount}" class="schedule-input">
    <button type="button" class="remove-schedule-btn" onclick="removeDeliverySchedule(this)">Remove</button>
  `;
  container.appendChild(newItem);
  
  // Show remove buttons for all items if more than 1
  if (deliveryScheduleCount > 1) {
    document.querySelectorAll('.remove-schedule-btn').forEach(btn => {
      btn.style.display = 'inline-block';
    });
  }
  console.log('Delivery schedule added, new count:', deliveryScheduleCount);
}

// Make functions globally accessible
window.addDeliverySchedule = addDeliverySchedule;

// Remove Delivery Schedule
function removeDeliverySchedule(button) {
  console.log('removeDeliverySchedule called');
  const container = document.getElementById('delivery_schedule_container');
  if (container.children.length > 1) {
    button.parentElement.remove();
    deliveryScheduleCount--;
    
    // Hide remove buttons if only 1 item left
    if (deliveryScheduleCount === 1) {
      document.querySelectorAll('.remove-schedule-btn').forEach(btn => {
        btn.style.display = 'none';
      });
    }
  }
}

// Make functions globally accessible
window.removeDeliverySchedule = removeDeliverySchedule;

// Close the first DOMContentLoaded event listener
});

// Event Listeners for Add Buttons
document.addEventListener('DOMContentLoaded', function() {
  console.log('Setting up Special Conditions event listeners...');
  
  const addPaymentBtn = document.getElementById('add_payment_milestone');
  const addScheduleBtn = document.getElementById('add_delivery_schedule');
  
  console.log('Add Payment Button found:', addPaymentBtn);
  console.log('Add Schedule Button found:', addScheduleBtn);
  
  if (addPaymentBtn) {
    addPaymentBtn.addEventListener('click', function(e) {
      e.preventDefault();
      console.log('Payment milestone button clicked');
      addPaymentMilestone();
    });
  }
  
  if (addScheduleBtn) {
    addScheduleBtn.addEventListener('click', function(e) {
      e.preventDefault();
      console.log('Delivery schedule button clicked');
      addDeliverySchedule();
    });
  }
});

// ─── Form Auto-Save Functionality ─────────────────────────────────────────

// Auto-save form data to localStorage
function saveFormData(formId, formData) {
  try {
    localStorage.setItem(`form_${formId}`, JSON.stringify(formData));
    console.log(`Form data saved for ${formId}`);
    
    // Show save indicator
    showSaveIndicator(formId);
  } catch (error) {
    console.error('Error saving form data:', error);
  }
}

// Show save indicator
function showSaveIndicator(formId) {
  const indicator = document.getElementById(`${formId}_save-indicator`);
  if (indicator) {
    indicator.classList.remove('hidden');
    indicator.style.opacity = '1';
    
    // Hide after 2 seconds
    setTimeout(() => {
      indicator.style.opacity = '0';
      setTimeout(() => {
        indicator.classList.add('hidden');
      }, 300);
    }, 2000);
  }
}

// Load form data from localStorage
function loadFormData(formId) {
  try {
    const savedData = localStorage.getItem(`form_${formId}`);
    return savedData ? JSON.parse(savedData) : null;
  } catch (error) {
    console.error('Error loading form data:', error);
    return null;
  }
}

// Clear saved form data
function clearFormData(formId) {
  try {
    localStorage.removeItem(`form_${formId}`);
    console.log(`Form data cleared for ${formId}`);
  } catch (error) {
    console.error('Error clearing form data:', error);
  }
}

// Collect all form data
function collectFormData(form) {
  const formData = {};
  const inputs = form.querySelectorAll('input, select, textarea');
  
  inputs.forEach(input => {
    if (input.name && input.type !== 'file') {
      if (input.type === 'checkbox' || input.type === 'radio') {
        formData[input.name] = input.checked;
      } else {
        formData[input.name] = input.value;
      }
    }
  });
  
  return formData;
}

// Restore form data
function restoreFormData(form, formData) {
  if (!formData) return;
  
  Object.keys(formData).forEach(name => {
    const input = form.querySelector(`[name="${name}"]`);
    if (input) {
      if (input.type === 'checkbox' || input.type === 'radio') {
        input.checked = formData[name];
      } else {
        input.value = formData[name];
        // Trigger change event for dependent fields
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }
  });
}

// Setup auto-save for a form
function setupAutoSave(formId, form) {
  const inputs = form.querySelectorAll('input, select, textarea');
  
  // Auto-save on input change
  inputs.forEach(input => {
    if (input.type !== 'file') {
      input.addEventListener('input', () => {
        const formData = collectFormData(form);
        saveFormData(formId, formData);
      });
      
      input.addEventListener('change', () => {
        const formData = collectFormData(form);
        saveFormData(formId, formData);
      });
    }
  });
  
  // Clear saved data on successful form submission
  form.addEventListener('submit', () => {
    // Clear after a short delay to ensure form submission completes
    setTimeout(() => {
      clearFormData(formId);
    }, 1000);
  });
}

// ─── Form Auto-Save Initialization ───────────────────────────────────────

// Initialize auto-save for forms when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  // Setup auto-save for Purchase Order form
  const generatePOForm = document.querySelector('form[action*="generate_form"]');
  if (generatePOForm) {
    setupAutoSave('po_form', generatePOForm);
    
    // Restore saved data on page load
    const savedPOData = loadFormData('po_form');
    if (savedPOData) {
      restoreFormData(generatePOForm, savedPOData);
      console.log('PO form data restored from localStorage');
    }
    
    // Clear data button
    const poClearBtn = document.getElementById('po-clear-data');
    if (poClearBtn) {
      poClearBtn.addEventListener('click', function() {
        if (confirm('Are you sure you want to clear all saved form data?')) {
          clearFormData('po_form');
          generatePOForm.reset();
          alert('Form data cleared successfully!');
        }
      });
    }
  }
  
  // Setup auto-save for Purchase Requisition form
  const generatePRForm = document.getElementById('PRForm');
  if (generatePRForm) {
    setupAutoSave('pr_form', generatePRForm);
    
    // Restore saved data on page load
    const savedPRData = loadFormData('pr_form');
    if (savedPRData) {
      restoreFormData(generatePRForm, savedPRData);
      console.log('PR form data restored from localStorage');
    }
    
    // Clear data button
    const prClearBtn = document.getElementById('pr-clear-data');
    if (prClearBtn) {
      prClearBtn.addEventListener('click', function() {
        if (confirm('Are you sure you want to clear all saved form data?')) {
          clearFormData('pr_form');
          generatePRForm.reset();
          alert('Form data cleared successfully!');
        }
      });
    }
  }
});
