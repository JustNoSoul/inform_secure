import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os
import re
from security_manager import SecurityManager, initialize_security

class User:
    def __init__(self, username, password="", restrictions=False, is_blocked=False, is_first_login=None, require_password_change=False):
        self.username = username
        self.password = password
        self.is_blocked = is_blocked
        self.password_restrictions = restrictions
        self.is_first_login = is_first_login if is_first_login is not None else (not password)
        self.require_password_change = require_password_change

class PasswordHelper:
    @staticmethod
    def validate_password_strength(password):
        if not password:
            return False
        
        has_letters = bool(re.search(r'[a-zA-Z]', password))
        has_punctuation = bool(re.search(r'[.,!?;:]', password))
        has_arithmetic = bool(re.search(r'[+\-*/=]', password))
        
        return has_letters and has_punctuation and has_arithmetic

class UserManager:
    def __init__(self, security_manager):
        self.security_manager = security_manager
        self.users = self.load_users()
        
        if not any(u.username == "ADMIN" for u in self.users):
            self.users.append(User("ADMIN", ""))
            self.save_users()
    
    def load_users(self):
        if not self.security_manager.temp_file:
            return []
            
        try:
            with open(self.security_manager.temp_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                users = []
                for user_data in data:
                    user = User(
                        username=user_data.get('username', ''),
                        password=user_data.get('password', ''),
                        restrictions=user_data.get('password_restrictions', False),
                        is_blocked=user_data.get('is_blocked', False),
                        is_first_login=user_data.get('is_first_login', None),
                        require_password_change=user_data.get('require_password_change', False)
                    )
                    users.append(user)
                return users
        except Exception as e:
            print(f"Ошибка загрузки: {e}")
            return []
    
    def save_users(self):
        try:
            if not self.security_manager.temp_file:
                return
                
            with open(self.security_manager.temp_file, 'w', encoding='utf-8') as f:
                data = []
                for user in self.users:
                    user_data = {
                        'username': user.username,
                        'password': user.password,
                        'is_blocked': user.is_blocked,
                        'password_restrictions': user.password_restrictions,
                        'is_first_login': user.is_first_login,
                        'require_password_change': user.require_password_change
                    }
                    data.append(user_data)
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.security_manager.save_changes()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка сохранения: {e}")
    
    def authenticate(self, username, password):
        user = next((u for u in self.users if u.username.upper() == username.upper()), None)
        if not user:
            raise Exception("Пользователь не найден")
        if user.is_blocked:
            raise Exception("Учетная запись заблокирована")
        if user.password != password:
            raise Exception("Неверный пароль")
        return user
    
    def user_exists(self, username):
        return any(u.username.upper() == username.upper() for u in self.users)
    
    def add_user(self, username):
        if self.user_exists(username):
            raise Exception("Пользователь с таким именем уже существует")
        self.users.append(User(username, ""))
        self.save_users()
    
    def update_user_password(self, user, new_password):
        user.password = new_password
        user.is_first_login = False
        user.require_password_change = False
        self.save_users()
    
    def toggle_user_block(self, username):
        user = next((u for u in self.users if u.username.upper() == username.upper()), None)
        if user:
            user.is_blocked = not user.is_blocked
            self.save_users()
            return user.is_blocked
        return False
    
    def toggle_password_restrictions(self, username):
        user = next((u for u in self.users if u.username.upper() == username.upper()), None)
        if user:
            old_restrictions = user.password_restrictions
            user.password_restrictions = not user.password_restrictions
            
            if user.password_restrictions and not old_restrictions and user.username != "ADMIN":
                if not PasswordHelper.validate_password_strength(user.password):
                    user.require_password_change = True
            if not user.password_restrictions and old_restrictions and user.username != "ADMIN":
                user.require_password_change = False
            
            self.save_users()
            return user.password_restrictions
        return False

class ChangePasswordWindow(tk.Toplevel):
    def __init__(self, parent, user, user_manager, is_first_login=False, require_change=False):
        super().__init__(parent)
        self.user = user
        self.user_manager = user_manager
        self.is_first_login = is_first_login
        self.require_change = require_change
        
        if require_change:
            self.title("Требуется смена пароля")
        else:
            self.title("Установка пароля" if is_first_login else "Смена пароля")
        
        self.geometry("450x300")
        self.transient(parent)
        self.grab_set()
        
        main_frame = tk.Frame(self)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        if require_change:
            warning_frame = tk.Frame(main_frame, bg='#fff3cd', relief=tk.RAISED, bd=1)
            warning_frame.pack(fill=tk.X, pady=(0, 15))
            warning_label = tk.Label(warning_frame, 
                                   text="⚠️ Администратор включил ограничения на пароли.\nНеобходимо установить новый пароль, соответствующий требованиям.",
                                   font=('Arial', 10), bg='#fff3cd', justify=tk.LEFT)
            warning_label.pack(padx=10, pady=10)
        
        if not is_first_login and not require_change:
            tk.Label(main_frame, text="Старый пароль:", font=('Arial', 11)).pack(pady=8)
            self.old_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11))
            self.old_password_entry.pack(pady=8, fill=tk.X)
        else:
            self.old_password_entry = None
        
        tk.Label(main_frame, text="Новый пароль:", font=('Arial', 11)).pack(pady=8)
        self.new_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11))
        self.new_password_entry.pack(pady=8, fill=tk.X)
        
        tk.Label(main_frame, text="Подтверждение:", font=('Arial', 11)).pack(pady=8)
        self.confirm_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11))
        self.confirm_password_entry.pack(pady=8, fill=tk.X)
        
        if self.user.password_restrictions or require_change:
            requirements_frame = tk.LabelFrame(main_frame, text="Требования к паролю", font=('Arial', 10))
            requirements_frame.pack(fill=tk.X, pady=10)
            
            requirements_text = """• Хотя бы одна буква (a-z, A-Z)
• Хотя бы один знак препинания (. , ! ? ; :)
• Хотя бы один арифметический знак (+ - * / =)"""
            
            tk.Label(requirements_frame, text=requirements_text, font=('Arial', 9), 
                    justify=tk.LEFT).pack(padx=10, pady=5)
        
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=15)
        
        if require_change:
            tk.Button(button_frame, text="Установить пароль", command=self.ok_click, 
                     font=('Arial', 11), width=15, height=2, bg='#d4edda').pack(side=tk.LEFT, padx=10)
        else:
            tk.Button(button_frame, text="OK", command=self.ok_click, 
                     font=('Arial', 11), width=10, height=2).pack(side=tk.LEFT, padx=10)
            tk.Button(button_frame, text="Отмена", command=self.cancel_click,
                     font=('Arial', 11), width=10, height=2).pack(side=tk.RIGHT, padx=10)
        
        self.result = False
    
    def ok_click(self):
        old_password = self.old_password_entry.get() if self.old_password_entry else ""
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not self.is_first_login and not self.require_change and self.user.password != old_password:
            messagebox.showerror("Ошибка", "Неверный старый пароль")
            return
        
        if new_password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return
        
        if self.require_change or self.user.password_restrictions:
            if not PasswordHelper.validate_password_strength(new_password):
                messagebox.showerror("Ошибка", 
                    "Пароль не соответствует требованиям:\n"
                    "- Хотя бы одна буква\n"
                    "- Хотя бы один знак препинания (. , ! ? ; :)\n"
                    "- Хотя бы один арифметический знак (+ - * / =)")
                return
        
        self.user_manager.update_user_password(self.user, new_password)
        self.result = True
        self.destroy()
    
    def cancel_click(self):
        if self.is_first_login or self.require_change:
            messagebox.showwarning("Внимание", "Для работы необходимо установить пароль")
            return
        self.destroy()

class ManageUsersWindow(tk.Toplevel):
    def __init__(self, parent, user_manager):
        super().__init__(parent)
        self.user_manager = user_manager
        self.current_index = 1
        
        self.title("Управление пользователями")
        self.geometry("600x400")
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        self.load_user_data()
    
    def create_widgets(self):
        main_frame = tk.Frame(self)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        info_frame = tk.LabelFrame(main_frame, text="Информация о пользователе", font=('Arial', 11))
        info_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(info_frame, text="Имя пользователя:", font=('Arial', 11)).grid(row=0, column=0, sticky=tk.W, padx=10, pady=10)
        self.username_label = tk.Label(info_frame, text="", font=('Arial', 11, 'bold'))
        self.username_label.grid(row=0, column=1, sticky=tk.W, padx=10, pady=10)
        
        self.blocked_var = tk.BooleanVar()
        self.blocked_check = tk.Checkbutton(info_frame, text="Заблокирован", 
                                           variable=self.blocked_var, font=('Arial', 11),
                                           command=self.toggle_blocked)
        self.blocked_check.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        self.restrictions_var = tk.BooleanVar()
        self.restrictions_check = tk.Checkbutton(info_frame, text="Ограничения на пароль", 
                                                variable=self.restrictions_var, font=('Arial', 11),
                                                command=self.toggle_restrictions)
        self.restrictions_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        tk.Label(info_frame, text="Статус пароля:", font=('Arial', 11)).grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        self.password_status_label = tk.Label(info_frame, text="", font=('Arial', 11))
        self.password_status_label.grid(row=3, column=1, sticky=tk.W, padx=10, pady=5)
        
        nav_frame = tk.Frame(main_frame)
        nav_frame.pack(pady=15)
        
        self.position_label = tk.Label(nav_frame, text="0 из 0", font=('Arial', 11))
        self.position_label.pack(pady=5)
        
        button_frame = tk.Frame(nav_frame)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="<< Первый", command=self.first_user,
                 font=('Arial', 11), width=12, height=2).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="< Предыдущий", command=self.previous_user,
                 font=('Arial', 11), width=12, height=2).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Следующий >", command=self.next_user,
                 font=('Arial', 11), width=12, height=2).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Последний >>", command=self.last_user,
                 font=('Arial', 11), width=12, height=2).pack(side=tk.LEFT, padx=5)
        
        tk.Button(main_frame, text="Закрыть", command=self.destroy,
                 font=('Arial', 11), width=15, height=2).pack(pady=10)
    
    def load_user_data(self):
        if self.user_manager.users:
            self.current_index = min(self.current_index, len(self.user_manager.users) - 1)
            self.display_user(self.current_index)
            self.update_navigation()
    
    def display_user(self, index):
        user = self.user_manager.users[index]
        self.username_label.config(text=user.username)
        self.blocked_var.set(user.is_blocked)
        self.restrictions_var.set(user.password_restrictions)
        
        status_parts = []
        if user.is_first_login:
            status_parts.append("Требуется установка")
        elif user.require_password_change:
            status_parts.append("Требуется смена")
        else:
            status_parts.append("Установлен")
        
        self.password_status_label.config(text=", ".join(status_parts))
        self.position_label.config(text=f"{index} из {len(self.user_manager.users)-1}")
    
    def update_navigation(self):
        pass
    
    def first_user(self):
        self.current_index = 1
        self.load_user_data()
    
    def previous_user(self):
        if self.current_index > 1:
            self.current_index -= 1
            self.load_user_data()
    
    def next_user(self):
        if self.current_index < len(self.user_manager.users) - 1:
            self.current_index += 1
            self.load_user_data()
    
    def last_user(self):
        self.current_index = len(self.user_manager.users) - 1
        self.load_user_data()
    
    def toggle_blocked(self):
        if self.username_label['text']:
            new_state = self.user_manager.toggle_user_block(self.username_label['text'])
            status = "заблокирован" if new_state else "разблокирован"
            messagebox.showinfo("Успех", f"Пользователь {status}")
    
    def toggle_restrictions(self):
        if self.username_label['text']:
            new_state = self.user_manager.toggle_password_restrictions(self.username_label['text'])
            status = "включены" if new_state else "выключены"
            messagebox.showinfo("Успех", f"Ограничения пароля {status}")

class AdminToolsWindow(tk.Toplevel):
    def __init__(self, parent, user_manager):
        super().__init__(parent)
        self.user_manager = user_manager
        
        self.title("Инструменты администратора")
        self.geometry("500x300")
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = tk.Frame(self)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        admin_frame = tk.LabelFrame(main_frame, text="Смена пароля администратора", font=('Arial', 11))
        admin_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(admin_frame, text="Сменить пароль ADMIN", command=self.change_admin_password,
                 font=('Arial', 11), width=20, height=2).pack(pady=15)
        
        user_frame = tk.LabelFrame(main_frame, text="Добавление пользователя", font=('Arial', 11))
        user_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(user_frame, text="Имя нового пользователя:", font=('Arial', 11)).pack(pady=5)
        
        input_frame = tk.Frame(user_frame)
        input_frame.pack(pady=10)
        
        self.new_username_entry = tk.Entry(input_frame, font=('Arial', 11))
        self.new_username_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Button(input_frame, text="Добавить", command=self.add_user,
                 font=('Arial', 11), width=10, height=1).pack(side=tk.LEFT, padx=5)
        
        tk.Button(main_frame, text="Закрыть", command=self.destroy,
                 font=('Arial', 11), width=15, height=2).pack(pady=15)
    
    def change_admin_password(self):
        admin = next((u for u in self.user_manager.users if u.username == "ADMIN"), None)
        if admin:
            ChangePasswordWindow(self, admin, self.user_manager)
        else:
            messagebox.showerror("Ошибка", "Администратор не найден")
    
    def add_user(self):
        username = self.new_username_entry.get().strip()
        if not username:
            messagebox.showerror("Ошибка", "Введите имя пользователя")
            return
        
        try:
            self.user_manager.add_user(username)
            messagebox.showinfo("Успех", f"Пользователь {username} добавлен")
            self.new_username_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

class LoginWindow:
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.authenticated_user = None
        
        self.root = tk.Tk()
        self.root.title("Вход в систему")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = tk.Frame(self.root)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="Имя пользователя:", font=('Arial', 11)).pack(pady=8)
        self.username_entry = tk.Entry(main_frame, font=('Arial', 11))
        self.username_entry.pack(pady=8, fill=tk.X)
        
        tk.Label(main_frame, text="Пароль:", font=('Arial', 11)).pack(pady=8)
        self.password_entry = tk.Entry(main_frame, show="*", font=('Arial', 11))
        self.password_entry.pack(pady=8, fill=tk.X)
        
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=15)
        
        tk.Button(button_frame, text="Войти", command=self.login,
                 font=('Arial', 11), width=10, height=2).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Отмена", command=self.cancel,
                 font=('Arial', 11), width=10, height=2).pack(side=tk.RIGHT, padx=10)
        
        self.username_entry.focus()
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username:
            messagebox.showerror("Ошибка", "Введите имя пользователя")
            return
        
        try:
            self.authenticated_user = self.user_manager.authenticate(username, password)
            
            if self.authenticated_user:
                if self.authenticated_user.require_password_change:
                    messagebox.showwarning("Требуется смена пароля", 
                                         "Администратор включил ограничения на пароли.\n"
                                         "Необходимо установить новый пароль, соответствующий требованиям.")
                    change_pass_window = ChangePasswordWindow(
                        self.root, self.authenticated_user, self.user_manager, 
                        require_change=True
                    )
                    self.root.wait_window(change_pass_window)
                    
                    if not change_pass_window.result:
                        self.authenticated_user = None
                        return
                
                elif self.authenticated_user.is_first_login:
                    messagebox.showinfo("Смена пароля", "Это ваш первый вход. Необходимо установить пароль.")
                    change_pass_window = ChangePasswordWindow(
                        self.root, self.authenticated_user, self.user_manager, True
                    )
                    self.root.wait_window(change_pass_window)
                    
                    if not change_pass_window.result:
                        self.authenticated_user = None
                        return
            
            self.root.destroy()
            
        except Exception as e:
            messagebox.showerror("Ошибка входа", str(e))
            self.password_entry.delete(0, tk.END)
            self.password_entry.focus()
    
    def cancel(self):
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()
        return self.authenticated_user

class MainApp:
    def __init__(self, user_manager, current_user):
        self.user_manager = user_manager
        self.current_user = current_user
        
        self.root = tk.Tk()
        self.root.title(f"Система аутентификации - {self.current_user.username}")
        self.root.geometry("500x400")
        
        self.create_widgets()
    
    def create_widgets(self):
        menu_frame = tk.Frame(self.root)
        menu_frame.pack(expand=True, padx=20, pady=20)
        
        welcome_label = tk.Label(menu_frame, text=f"Добро пожаловать, {self.current_user.username}!", 
                                font=('Arial', 14, 'bold'))
        welcome_label.pack(pady=20)
        
        button_width = 25
        button_height = 2
        button_font = ('Arial', 12)
        
        change_pass_btn = tk.Button(menu_frame, text="Сменить пароль", 
                                   command=self.change_password,
                                   font=button_font, width=button_width, height=button_height)
        change_pass_btn.pack(pady=10)
        
        if self.current_user.username == "ADMIN":
            manage_users_btn = tk.Button(menu_frame, text="Управление пользователями", 
                                       command=self.manage_users,
                                       font=button_font, width=button_width, height=button_height)
            manage_users_btn.pack(pady=10)
            
            admin_tools_btn = tk.Button(menu_frame, text="Инструменты администратора", 
                                      command=self.admin_tools,
                                      font=button_font, width=button_width, height=button_height)
            admin_tools_btn.pack(pady=10)
        
        exit_btn = tk.Button(menu_frame, text="Выход", command=self.root.quit,
                           font=button_font, width=button_width, height=button_height)
        exit_btn.pack(pady=10)
        
        status_text = f"Пользователь: {self.current_user.username} | "
        status_text += "Администратор" if self.current_user.username == "ADMIN" else "Пользователь"
        status_text += f" | {'Заблокирован' if self.current_user.is_blocked else 'Активен'}"
        status_text += f" | {'Ограничения включены' if self.current_user.password_restrictions else 'Ограничения выключены'}"
        
        status_label = tk.Label(self.root, text=status_text, relief=tk.SUNKEN, 
                               anchor=tk.W, font=('Arial', 10))
        status_label.pack(side=tk.BOTTOM, fill=tk.X)
    
    def change_password(self):
        ChangePasswordWindow(self.root, self.current_user, self.user_manager)
    
    def manage_users(self):
        ManageUsersWindow(self.root, self.user_manager)
    
    def admin_tools(self):
        AdminToolsWindow(self.root, self.user_manager)
    
    def run(self):
        self.root.mainloop()

def main():
    security_mgr = initialize_security()
    if not security_mgr:
        return
    
    try:
        user_manager = UserManager(security_mgr)
        
        login_window = LoginWindow(user_manager)
        current_user = login_window.run()
        
        if current_user:
            app = MainApp(user_manager, current_user)
            app.run()
        
    except Exception as e:
        messagebox.showerror("Критическая ошибка", f"Ошибка запуска приложения: {e}")
    finally:
        if 'security_mgr' in locals():
            security_mgr.cleanup()

if __name__ == "__main__":
    main()