// Authentication and forum functionality
let currentUser = null;
let authToken = null;

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    checkAuthStatus();
    loadCategories();
    loadPosts();
});

// Auth modal functions
function showAuthModal() {
    document.getElementById('authModal').style.display = 'block';
}

function closeAuthModal() {
    document.getElementById('authModal').style.display = 'none';
}

// Create post modal functions
function showCreatePostModal() {
    if (!currentUser) {
        showAuthModal();
        return;
    }
    document.getElementById('createPostModal').style.display = 'block';
    loadCategoriesForPost();
}

function closeCreatePostModal() {
    document.getElementById('createPostModal').style.display = 'none';
}

// Admin modal functions
function showAdminModal() {
    document.getElementById('adminModal').style.display = 'block';
    loadAdminData();
}

function closeAdminModal() {
    document.getElementById('adminModal').style.display = 'none';
}

// Google Sign-In handler
async function handleGoogleSignIn(response) {
    try {
        const res = await fetch('/auth/google', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token: response.credential })
        });

        const data = await res.json();
        
        if (data.success) {
            authToken = data.token;
            currentUser = data.user;
            updateUI();
            closeAuthModal();
            
            if (currentUser.role === 'admin') {
                document.getElementById('adminPanelLink').style.display = 'block';
            }
        } else {
            alert('Ошибка авторизации: ' + data.error);
        }
    } catch (error) {
        console.error('Auth error:', error);
        alert('Ошибка соединения');
    }
}

// Check auth status
async function checkAuthStatus() {
    const token = localStorage.getItem('forum_token');
    if (token) {
        try {
            const res = await fetch('/auth/verify', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (res.ok) {
                const data = await res.json();
                authToken = token;
                currentUser = data.user;
                updateUI();
            } else {
                localStorage.removeItem('forum_token');
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            localStorage.removeItem('forum_token');
        }
    }
}

// Update UI based on auth status
function updateUI() {
    const navActions = document.getElementById('navActions');
    const userMenu = document.getElementById('userMenu');
    
    if (currentUser) {
        navActions.style.display = 'none';
        userMenu.style.display = 'flex';
        document.getElementById('userAvatar').src = currentUser.avatar;
        document.getElementById('userName').textContent = currentUser.name;
        
        if (currentUser.role === 'admin') {
            document.getElementById('adminPanelLink').style.display = 'block';
        }
        
        localStorage.setItem('forum_token', authToken);
    } else {
        navActions.style.display = 'block';
        userMenu.style.display = 'none';
        localStorage.removeItem('forum_token');
    }
}

// Logout
function logout() {
    currentUser = null;
    authToken = null;
    localStorage.removeItem('forum_token');
    updateUI();
    
    // Google logout
    google.accounts.id.disableAutoSelect();
}

// Load categories
async function loadCategories() {
    try {
        const res = await fetch('/api/categories');
        const categories = await res.json();
        
        const grid = document.getElementById('categoriesGrid');
        grid.innerHTML = categories.map(cat => `
            <div class="category-card" onclick="viewCategory(${cat.id})">
                <div class="category-header">
                    <div class="category-icon">
                        <i class="fas ${cat.icon || 'fa-folder'}"></i>
                    </div>
                    <div class="category-info">
                        <h3>${cat.name}</h3>
                        <p>${cat.description}</p>
                    </div>
                </div>
                <div class="category-stats">
                    <small>${cat.post_count} постов</small>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load categories:', error);
    }
}

// Load posts
async function loadPosts() {
    try {
        const sortBy = document.getElementById('sortSelect').value;
        const res = await fetch(`/api/posts?sort=${sortBy}&limit=10`);
        const posts = await res.json();
        
        const postsList = document.getElementById('postsList');
        postsList.innerHTML = posts.map(post => `
            <div class="post-card">
                <div class="post-header">
                    <a href="#" class="post-title" onclick="viewPost(${post.id})">${post.title}</a>
                    <span class="post-category">${post.category_name}</span>
                </div>
                <div class="post-meta">
                    <span>${post.author_name}</span>
                    <span>${new Date(post.created_at).toLocaleDateString()}</span>
                    <span>${post.comment_count} комментариев</span>
                </div>
                <div class="post-excerpt">${post.content.substring(0, 200)}...</div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load posts:', error);
    }
}

// Create post
document.getElementById('createPostForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    if (!currentUser) {
        showAuthModal();
        return;
    }
    
    const formData = new FormData();
    formData.append('title', document.getElementById('postTitle').value);
    formData.append('category_id', document.getElementById('postCategory').value);
    formData.append('content', document.getElementById('postContent').value);
    
    const fileInput = document.getElementById('postFile');
    if (fileInput.files[0]) {
        formData.append('file', fileInput.files[0]);
    }
    
    try {
        const res = await fetch('/api/posts', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            },
            body: formData
        });
        
        if (res.ok) {
            closeCreatePostModal();
            loadPosts();
            this.reset();
        } else {
            alert('Ошибка при создании поста');
        }
    } catch (error) {
        console.error('Failed to create post:', error);
        alert('Ошибка соединения');
    }
});

// Admin functions
function openAdminTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(tabName + 'Tab').classList.add('active');
}

async function loadAdminData() {
    if (!currentUser || currentUser.role !== 'admin') return;
    
    await loadAdminCategories();
    await loadAdminUsers();
    await loadAdminPosts();
}

async function loadAdminCategories() {
    const res = await fetch('/api/admin/categories', {
        headers: { 'Authorization': `Bearer ${authToken}` }
    });
    const categories = await res.json();
    
    const list = document.getElementById('adminCategoriesList');
    list.innerHTML = categories.map(cat => `
        <div class="admin-item">
            <span>${cat.name} - ${cat.description}</span>
            <div>
                <button onclick="editCategory(${cat.id})">Редактировать</button>
                <button onclick="deleteCategory(${cat.id})" class="btn-danger">Удалить</button>
            </div>
        </div>
    `).join('');
}

// Load categories for post creation
async function loadCategoriesForPost() {
    const res = await fetch('/api/categories');
    const categories = await res.json();
    
    const select = document.getElementById('postCategory');
    select.innerHTML = '<option value="">Выберите категорию</option>' +
        categories.map(cat => `<option value="${cat.id}">${cat.name}</option>`).join('');
}

// Placeholder functions for future implementation
function viewCategory(categoryId) {
    alert('Просмотр категории ' + categoryId);
}

function viewPost(postId) {
    alert('Просмотр поста ' + postId);
}

// Close modals when clicking outside
window.onclick = function(event) {
    const modals = document.getElementsByClassName('modal');
    for (let modal of modals) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    }
}
