import React, { useState, useEffect } from 'react';
import { MessageCircle, Users, BookOpen, Trophy, Settings, LogOut, Send, Star, Zap, Award, TrendingUp, Calendar, Bell, Search, Plus, X, Check, Brain, Edit2, Trash2, LogIn, UserPlus } from 'lucide-react';

const API_URL = 'http://localhost:5000/api';

export default function MythAIPortal() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [showLogin, setShowLogin] = useState(true);
  const [user, setUser] = useState(null);
  const [view, setView] = useState('dashboard');
  const [selectedClass, setSelectedClass] = useState(null);
  const [classes, setClasses] = useState([]);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [showAIAssistant, setShowAIAssistant] = useState(false);
  const [aiQuery, setAiQuery] = useState('');
  const [aiResponse, setAiResponse] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [registerForm, setRegisterForm] = useState({ username: '', email: '', password: '', role: 'student' });
  const [joinClassCode, setJoinClassCode] = useState('');
  const [showJoinClass, setShowJoinClass] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      loadClasses();
    }
  }, [isAuthenticated]);

  useEffect(() => {
    if (selectedClass) {
      loadMessages(selectedClass.id);
    }
  }, [selectedClass]);

  const checkAuth = async () => {
    try {
      const res = await fetch(`${API_URL}/me`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data);
        setIsAuthenticated(true);
      }
    } catch (err) {
      console.log('Not authenticated');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(loginForm)
      });
      
      if (res.ok) {
        const data = await res.json();
        setUser(data);
        setIsAuthenticated(true);
      } else {
        const err = await res.json();
        setError(err.error || 'Login failed');
      }
    } catch (err) {
      setError('Connection error');
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const res = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(registerForm)
      });
      
      if (res.ok) {
        const data = await res.json();
        setUser(data);
        setIsAuthenticated(true);
      } else {
        const err = await res.json();
        setError(err.error || 'Registration failed');
      }
    } catch (err) {
      setError('Connection error');
    }
  };

  const handleLogout = async () => {
    await fetch(`${API_URL}/logout`, {
      method: 'POST',
      credentials: 'include'
    });
    setIsAuthenticated(false);
    setUser(null);
    setClasses([]);
    setMessages([]);
  };

  const loadClasses = async () => {
    try {
      const res = await fetch(`${API_URL}/classes`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setClasses(data);
      }
    } catch (err) {
      console.error('Failed to load classes');
    }
  };

  const loadMessages = async (classId) => {
    try {
      const res = await fetch(`${API_URL}/classes/${classId}/messages`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setMessages(data);
      }
    } catch (err) {
      console.error('Failed to load messages');
    }
  };

  const sendMessage = async () => {
    if (!newMessage.trim() || !selectedClass) return;
    
    try {
      const res = await fetch(`${API_URL}/classes/${selectedClass.id}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ content: newMessage })
      });
      
      if (res.ok) {
        const msg = await res.json();
        setMessages([msg, ...messages]);
        setNewMessage('');
        
        if (user && user.stats) {
          setUser({...user, stats: {...user.stats, points: user.stats.points + 5}});
        }
      }
    } catch (err) {
      console.error('Failed to send message');
    }
  };

  const addReaction = async (msgId, emoji) => {
    try {
      const res = await fetch(`${API_URL}/messages/${msgId}/react`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ emoji })
      });
      
      if (res.ok) {
        const reactions = await res.json();
        setMessages(messages.map(msg => 
          msg.id === msgId ? {...msg, reactions} : msg
        ));
      }
    } catch (err) {
      console.error('Failed to add reaction');
    }
  };

  const joinClass = async () => {
    if (!joinClassCode.trim()) return;
    
    try {
      const res = await fetch(`${API_URL}/classes/join`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ code: joinClassCode })
      });
      
      if (res.ok) {
        setShowJoinClass(false);
        setJoinClassCode('');
        loadClasses();
      } else {
        const err = await res.json();
        setError(err.error);
      }
    } catch (err) {
      setError('Failed to join class');
    }
  };

  const handleAIQuery = async () => {
    if (!aiQuery.trim()) return;
    
    setIsTyping(true);
    setAiResponse('');
    
    try {
      const res = await fetch(`${API_URL}/ai/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ query: aiQuery })
      });
      
      if (res.ok) {
        const data = await res.json();
        setAiResponse(data.response);
      }
    } catch (err) {
      setAiResponse('Sorry, I encountered an error. Please try again.');
    }
    
    setIsTyping(false);
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-2xl shadow-2xl p-8 w-full max-w-md">
          <div className="flex items-center justify-center gap-3 mb-8">
            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
              <Brain className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-white">Myth AI Portal</h1>
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500 text-red-200 rounded-lg p-3 mb-4">
              {error}
            </div>
          )}

          {showLogin ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <h2 className="text-2xl font-bold text-white mb-4">Login</h2>
              
              <div>
                <label className="block text-gray-300 mb-2">Email</label>
                <input
                  type="email"
                  value={loginForm.email}
                  onChange={(e) => setLoginForm({...loginForm, email: e.target.value})}
                  className="w-full bg-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="student@demo.com"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 mb-2">Password</label>
                <input
                  type="password"
                  value={loginForm.password}
                  onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                  className="w-full bg-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="password123"
                  required
                />
              </div>

              <button
                type="submit"
                className="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 rounded-lg transition flex items-center justify-center gap-2"
              >
                <LogIn className="w-5 h-5" />
                Login
              </button>

              <p className="text-center text-gray-400 mt-4">
                Don't have an account?{' '}
                <button
                  type="button"
                  onClick={() => {
                    setShowLogin(false);
                    setError('');
                  }}
                  className="text-blue-400 hover:text-blue-300"
                >
                  Register
                </button>
              </p>

              <div className="mt-4 p-3 bg-gray-700 rounded-lg">
                <p className="text-gray-300 text-sm">Demo Accounts:</p>
                <p className="text-gray-400 text-xs mt-1">Student: student@demo.com / password123</p>
                <p className="text-gray-400 text-xs">Teacher: teacher@demo.com / password123</p>
              </div>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="space-y-4">
              <h2 className="text-2xl font-bold text-white mb-4">Register</h2>
              
              <div>
                <label className="block text-gray-300 mb-2">Username</label>
                <input
                  type="text"
                  value={registerForm.username}
                  onChange={(e) => setRegisterForm({...registerForm, username: e.target.value})}
                  className="w-full bg-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 mb-2">Email</label>
                <input
                  type="email"
                  value={registerForm.email}
                  onChange={(e) => setRegisterForm({...registerForm, email: e.target.value})}
                  className="w-full bg-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 mb-2">Password</label>
                <input
                  type="password"
                  value={registerForm.password}
                  onChange={(e) => setRegisterForm({...registerForm, password: e.target.value})}
                  className="w-full bg-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 mb-2">I am a...</label>
                <select
                  value={registerForm.role}
                  onChange={(e) => setRegisterForm({...registerForm, role: e.target.value})}
                  className="w-full bg-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="student">Student</option>
                  <option value="teacher">Teacher</option>
                </select>
              </div>

              <button
                type="submit"
                className="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 rounded-lg transition flex items-center justify-center gap-2"
              >
                <UserPlus className="w-5 h-5" />
                Register
              </button>

              <p className="text-center text-gray-400 mt-4">
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={() => {
                    setShowLogin(true);
                    setError('');
                  }}
                  className="text-blue-400 hover:text-blue-300"
                >
                  Login
                </button>
              </p>
            </form>
          )}
        </div>
      </div>
    );
  }

  const DashboardView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Total Points</p>
              <p className="text-3xl font-bold mt-1">{user?.stats?.points || 0}</p>
            </div>
            <Trophy className="w-12 h-12 opacity-50" />
          </div>
        </div>
        
        <div className="bg-gradient-to-br from-orange-500 to-red-600 rounded-2xl p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-orange-100 text-sm">Current Streak</p>
              <p className="text-3xl font-bold mt-1">{user?.stats?.streak || 0} days</p>
            </div>
            <Zap className="w-12 h-12 opacity-50" />
          </div>
        </div>
        
        <div className="bg-gradient-to-br from-purple-500 to-purple-600 rounded-2xl p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-purple-100 text-sm">Level</p>
              <p className="text-3xl font-bold mt-1">{user?.stats?.level || 1}</p>
            </div>
            <Award className="w-12 h-12 opacity-50" />
          </div>
        </div>
        
        <div className="bg-gradient-to-br from-green-500 to-green-600 rounded-2xl p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-100 text-sm">Classes</p>
              <p className="text-3xl font-bold mt-1">{classes.length}</p>
            </div>
            <BookOpen className="w-12 h-12 opacity-50" />
          </div>
        </div>
      </div>

      <div className="bg-gray-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white">My Classes</h2>
          <button
            onClick={() => setShowJoinClass(true)}
            className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition"
          >
            <Plus className="w-4 h-4" />
            Join Class
          </button>
        </div>
        
        {classes.length === 0 ? (
          <div className="text-center py-12">
            <BookOpen className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No classes yet. Join one to get started!</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {classes.map(cls => (
              <div
                key={cls.id}
                onClick={() => {
                  setSelectedClass(cls);
                  setView('chat');
                }}
                className="bg-gray-700 hover:bg-gray-600 rounded-xl p-6 cursor-pointer transition group"
              >
                <div className={`w-12 h-12 ${cls.color} rounded-lg flex items-center justify-center mb-4 group-hover:scale-110 transition`}>
                  <BookOpen className="w-6 h-6 text-white" />
                </div>
                <h3 className="text-white font-semibold mb-1">{cls.name}</h3>
                <p className="text-gray-400 text-sm mb-3">{cls.teacher}</p>
                <div className="flex items-center text-gray-400 text-sm">
                  <Users className="w-4 h-4 mr-1" />
                  {cls.student_count} students
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  const ChatView = () => (
    <div className="h-full flex flex-col">
      <div className="bg-gray-800 rounded-t-2xl p-6 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-white">{selectedClass?.name}</h2>
            <p className="text-gray-400 text-sm">{selectedClass?.teacher}</p>
          </div>
          <button
            onClick={() => setShowAIAssistant(!showAIAssistant)}
            className="bg-purple-500 hover:bg-purple-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition"
          >
            <Brain className="w-4 h-4" />
            AI Tutor
          </button>
        </div>
      </div>

      <div className="flex-1 bg-gray-800 p-6 overflow-y-auto">
        {messages.length === 0 ? (
          <div className="text-center py-12">
            <MessageCircle className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No messages yet. Start the conversation!</p>
          </div>
        ) : (
          <div className="space-y-4">
            {messages.map(msg => (
              <div key={msg.id} className="bg-gray-700 rounded-xl p-4">
                <div className="flex items-start gap-4">
                  <div className="text-3xl">{msg.avatar}</div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-white font-semibold">{msg.user}</span>
                      <span className="text-gray-400 text-sm">{msg.timestamp}</span>
                    </div>
                    <p className="text-gray-200 mb-3">{msg.content}</p>
                    <div className="flex gap-2">
                      {['👍', '❤️', '🔥', '✅'].map(emoji => (
                        <button
                          key={emoji}
                          onClick={() => addReaction(msg.id, emoji)}
                          className="bg-gray-600 hover:bg-gray-500 px-3 py-1 rounded-lg text-sm transition"
                        >
                          {emoji} {msg.reactions?.[emoji] || 0}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-gray-800 rounded-b-2xl p-6 border-t border-gray-700">
        <div className="flex gap-3">
          <input
            type="text"
            value={newMessage}
            onChange={(e) => setNewMessage(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
            placeholder="Type your message..."
            className="flex-1 bg-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            onClick={sendMessage}
            className="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg flex items-center gap-2 transition"
          >
            <Send className="w-5 h-5" />
          </button>
        </div>
      </div>

      {showAIAssistant && (
        <div className="fixed right-6 bottom-6 w-96 bg-gray-800 rounded-2xl shadow-2xl border border-gray-700">
          <div className="p-4 border-b border-gray-700 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Brain className="w-5 h-5 text-purple-400" />
              <h3 className="font-bold text-white">AI Tutor</h3>
            </div>
            <button
              onClick={() => setShowAIAssistant(false)}
              className="text-gray-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          
          <div className="p-4 h-96 overflow-y-auto">
            {aiResponse && (
              <div className="bg-gray-700 rounded-lg p-4 mb-4">
                <p className="text-gray-200 whitespace-pre-wrap">{aiResponse}</p>
              </div>
            )}
            {isTyping && (
              <div className="bg-gray-700 rounded-lg p-4 mb-4">
                <div className="flex gap-2">
                  <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                  <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{animationDelay: '0.4s'}}></div>
                </div>
              </div>
            )}
          </div>
          
          <div className="p-4 border-t border-gray-700">
            <div className="flex gap-2">
              <input
                type="text"
                value={aiQuery}
                onChange={(e) => setAiQuery(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleAIQuery()}
                placeholder="Ask me anything..."
                className="flex-1 bg-gray-700 text-white rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
              <button
                onClick={handleAIQuery}
                className="bg-purple-500 hover:bg-purple-600 text-white px-4 py-2 rounded-lg transition"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <nav className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
              <Brain className="w-6 h-6" />
            </div>
            <h1 className="text-2xl font-bold">Myth AI Portal</h1>
          </div>
          
          <div className="flex items-center gap-6">
            <button className="text-gray-400 hover:text-white transition">
              <Bell className="w-6 h-6" />
            </button>
            <div className="flex items-center gap-3">
              <span className="text-3xl">{user?.avatar}</span>
              <div>
                <p className="font-semibold">{user?.username}</p>
                <p className="text-sm text-gray-400">Level {user?.stats?.level || 1}</p>
              </div>
            </div>
          </div>
        </div>
      </nav>

      <div className="flex">
        <aside className="w-64 bg-gray-800 min-h-screen border-r border-gray-700 p-6">
          <nav className="space-y-2">
            <button
              onClick={() => setView('dashboard')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                view === 'dashboard' ? 'bg-blue-500 text-white' : 'text-gray-400 hover:bg-gray-700 hover:text-white'
              }`}
            >
              <TrendingUp className="w-5 h-5" />
              Dashboard
            </button>
            
            <button
              onClick={() => {
                if (classes.length > 0) {
                  setSelectedClass(classes[0]);
                  setView('chat');
                }
              }}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                view === 'chat' ? 'bg-blue-500 text-white' : 'text-gray-400 hover:bg-gray-700 hover:text-white'
              }`}
            >
              <MessageCircle className="w-5 h-5" />
              Chat
            </button>
            
            <button
              onClick={() => setView('settings')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                view === 'settings' ? 'bg-blue-500 text-white' : 'text-gray-400 hover:bg-gray-700 hover:text-white'
              }`}
            >
              <Settings className="w-5 h-5" />
              Settings
            </button>
          </nav>
          
          <div className="mt-8 pt-8 border-t border-gray-700">
            <button
              onClick={handleLogout}
              className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-red-400 hover:bg-gray-700 transition"
            >
              <LogOut className="w-5 h-5" />
              Logout
            </button>
          </div>
        </aside>

        <main className="flex-1 p-8">
          {view === 'dashboard' && <DashboardView />}
          {view === 'chat' && <ChatView />}
          {view === 'settings' && (
            <div className="bg-gray-800 rounded-2xl p-6">
              <h2 className="text-2xl font-bold mb-6">Settings</h2>
              <p className="text-gray-400">Settings panel coming soon...</p>
            </div>
          )}
        </main>
      </div>

      {showJoinClass && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold text-white">Join a Class</h3>
              <button
                onClick={() => setShowJoinClass(false)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            
            {error && (
              <div className="bg-red-500/20 border border-red-500 text-red-200 rounded-lg p-3 mb-4">
                {error}
              </div>
            )}
            
            <input
              type="text"
              value={joinClassCode}
              onChange={(e) => setJoinClassCode(e.target.value.toUpperCase())}
              placeholder="Enter class code (e.g., DEMO1234)"
              className="w-full bg-gray-700 text-white rounded-lg px-4 py-3 mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            
            <button
              onClick={joinClass}
              className="w-full bg-blue-500 hover:bg-blue-600 text-white py-3 rounded-lg transition"
            >
              Join Class
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
