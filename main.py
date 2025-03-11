import wmi
import winreg
import subprocess
import os
import ctypes
import sys
from datetime import datetime
from colorama import Fore, init
import json
# Инициализация цветного вывода
init(autoreset=True)


def run_as_admin():
    """Перезапуск скрипта с правами администратора"""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([script] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)


def print_header(text):
    """Вывод заголовка с оформлением"""
    print(Fore.CYAN + "\n" + "=" * 50)
    print(Fore.YELLOW + f" {text}")
    print(Fore.CYAN + "=" * 50)


def print_status(item, status):
    """Форматированный вывод статусов"""
    color = Fore.GREEN if status in ["Да", "Включен", "Активен"] else Fore.RED if status in ["Нет", "Выключен",
                                                                                             "Неактивен"] else Fore.WHITE
    print(Fore.WHITE + f"{item.ljust(35)}: {color}{status}")


def format_bios_date(bios_date):
    """Преобразование даты BIOS в читаемый формат"""
    try:
        return datetime.strptime(bios_date.split('.')[0], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except:
        return bios_date


def get_bios_info():
    """Получение информации о BIOS"""
    try:
        c = wmi.WMI()
        bios = c.Win32_BIOS()[0]
        return {
            "Производитель": bios.Manufacturer,
            "Версия BIOS": bios.SMBIOSBIOSVersion,
            "Дата BIOS": format_bios_date(bios.ReleaseDate),
            "Режим BIOS": "UEFI" if bios.BiosCharacteristics and 41 in bios.BiosCharacteristics else "Legacy"
        }
    except Exception as e:
        return {"Ошибка": str(e)}


def check_partition_style_powershell():
    """Получение стиля разделов через PowerShell с улучшенной обработкой ошибок"""
    try:
        output = subprocess.check_output(
            ["powershell", "Get-Disk | Select-Object Number, PartitionStyle | ConvertTo-Json"],
            text=True,
            stderr=subprocess.STDOUT,
            shell=True
        ).strip()

        if not output:
            return {}

        disks = json.loads(output)

        # Обработка разных форматов вывода
        if isinstance(disks, dict):  # Для одного диска
            return {disks["Number"]: disks["PartitionStyle"]}
        elif isinstance(disks, list):  # Для нескольких дисков
            return {disk["Number"]: disk["PartitionStyle"] for disk in disks}

        return {}

    except Exception as e:
        print(Fore.RED + f"Ошибка PowerShell: {str(e)}")
        print(Fore.YELLOW + f"Вывод команды: {output if 'output' in locals() else ''}")
        return {}

def format_size(size_bytes):
    """Форматирование размера в читаемый вид"""
    try:
        return f"{int(int(size_bytes) // (1024 ** 3))} GB" if size_bytes else "0 GB"
    except:
        return "Н/Д"

def get_disk_partitions():
    """Получение информации о дисках с улучшенной обработкой ошибок"""
    try:
        result = []
        c = wmi.WMI()
        ps_style = check_partition_style_powershell()

        for physical_disk in c.Win32_DiskDrive():
            try:
                disk_info = {
                    "Физический диск": getattr(physical_disk, "Caption", "Неизвестно"),
                    "Номер": int(getattr(physical_disk, "Index", -1)),
                    "Стиль раздела": "Неизвестно",
                    "Размер": format_size(getattr(physical_disk, "Size", 0)),
                    "Разделы": []
                }

                # Определение стиля раздела
                try:
                    disk_info["Стиль раздела"] = ps_style.get(
                        disk_info["Номер"],
                        {1: "MBR", 2: "GPT"}.get(
                            int(getattr(physical_disk, "PartitionStyle", 0)),
                            "Неизвестно"
                        )
                    )
                except Exception as e:
                    disk_info["Стиль раздела"] = f"Ошибка: {str(e)}"

                # Получение информации о разделах
                try:
                    for partition in physical_disk.associators("Win32_DiskDriveToDiskPartition"):
                        for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                            disk_info["Разделы"].append({
                                "Буква": getattr(logical_disk, "Caption", "Без буквы"),
                                "Файловая система": getattr(logical_disk, "FileSystem", "Неизвестно"),
                                "Размер": format_size(getattr(logical_disk, "Size", 0)),
                                "Свободно": format_size(getattr(logical_disk, "FreeSpace", 0))
                            })
                except Exception as e:
                    disk_info["Ошибка разделов"] = str(e)

                result.append(disk_info)

            except Exception as e:
                print(Fore.RED + f"Ошибка обработки диска: {str(e)}")
                continue

        return result

    except Exception as e:
        print(Fore.RED + f"Критическая ошибка: {str(e)}")
        return []





def get_windows_info():
    """Получение информации о Windows"""
    try:
        c = wmi.WMI()
        os_info = c.Win32_OperatingSystem()[0]  # Получаем первый объект ОС

        result = {}

        # Проверка и добавление данных с обработкой исключений
        try:
            result["Версия"] = os_info.Caption
        except AttributeError:
            result["Версия"] = "Неизвестно"

        try:
            result["Сборка"] = os_info.BuildNumber
        except AttributeError:
            result["Сборка"] = "Н/Д"

        try:
            result["Архитектура"] = os_info.OSArchitecture
        except AttributeError:
            result["Архитектура"] = "Н/Д"

        try:
            result["Лицензия"] = "Активирована" if os_info.LicenseStatus == 1 else "Не активирована"
        except AttributeError:
            result["Лицензия"] = "Статус неизвестен"

        try:
            install_date = datetime.strptime(os_info.InstallDate.split('.')[0], "%Y%m%d%H%M%S")
            result["Дата установки"] = install_date.strftime("%Y-%m-%d %H:%M:%S")
        except:
            result["Дата установки"] = "Н/Д"

        return result

    except Exception as e:
        print(Fore.RED + f"\nОшибка получения данных ОС: {str(e)}")
        return {
            "Версия": "Ошибка",
            "Сборка": "Ошибка",
            "Архитектура": "Ошибка",
            "Лицензия": "Ошибка"
        }


def get_cpu_info():
    try:
        c = wmi.WMI()
        cpu = c.Win32_Processor()[0]
        return {
            "Модель": cpu.Name,
            "Ядра": cpu.NumberOfCores,
            "Потоки": cpu.NumberOfLogicalProcessors,
            "Виртуализация": "Включена" if cpu.VirtualizationFirmwareEnabled else "Выключена"
        }
    except:
        return {}


def get_gpu_info():
    try:
        c = wmi.WMI()
        return [{"Модель": gpu.Name, "Память": f"{int(gpu.AdapterRAM / (1024 ** 3))} GB"} for gpu in
                c.Win32_VideoController()]
    except:
        return []


def check_secure_boot():
    try:
        output = subprocess.check_output(
            ["powershell", "Confirm-SecureBootUEFI"],
            text=True, stderr=subprocess.STDOUT
        ).strip()
        return "Да" if output == "True" else "Нет"
    except subprocess.CalledProcessError as e:
        return "Не поддерживается"


def check_tpm():
    try:
        c = wmi.WMI()
        tpm = c.Win32_Tpm()[0]
        return "Да" if tpm.IsActivated_InitialValue and tpm.IsEnabled_InitialValue else "Нет"
    except:
        return "Нет"


def check_virtualization():
    try:
        c = wmi.WMI()
        return "Да" if c.Win32_ComputerSystem()[0].VirtualizationFirmwareEnabled else "Нет"
    except:
        return "Нет"


def check_kernel_isolation():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        )
        value, _ = winreg.QueryValueEx(key, "Enabled")
        return "Да" if value == 1 else "Нет"
    except:
        return "Нет"


def check_dma_protection():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Policies\Microsoft\Windows\Kernel DMA Protection"
        )
        value, _ = winreg.QueryValueEx(key, "DeviceEnumerationPolicy")
        return "Да" if value == 1 else "Нет"
    except:
        return "Нет"


def check_smartscreen():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        )
        value, _ = winreg.QueryValueEx(key, "SmartScreenEnabled")
        return "Включен" if value in ["RequireAdmin", "Warn", "On"] else "Выключен"
    except:
        return "Ошибка проверки"


def check_defender():
    try:
        c = wmi.WMI()
        service = c.Win32_Service(Name='WinDefend')[0]
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        )
        rt_disabled, _ = winreg.QueryValueEx(key, "DisableRealtimeMonitoring")
        return "Активен" if service.State == 'Running' and rt_disabled == 0 else "Неактивен"
    except:
        return "Ошибка проверки"


def check_firewall():
    try:
        c = wmi.WMI()
        service = c.Win32_Service(Name='MpsSvc')[0]
        return "Активен" if service.State == 'Running' else "Выключен"
    except:
        return "Ошибка проверки"


def check_installed_software(keywords):
    found = []
    try:
        c = wmi.WMI()
        for product in c.Win32_Product():
            for kw in keywords:
                if kw.lower() in product.Name.lower():
                    found.append(kw)
    except:
        pass
    return list(set(found))


def check_running_processes(keywords):
    found = []
    try:
        c = wmi.WMI()
        for process in c.Win32_Process():
            for kw in keywords:
                if kw.lower() in process.Name.lower():
                    found.append(kw)
    except:
        pass
    return list(set(found))


if __name__ == "__main__":
    run_as_admin()

    try:
        print_header("СИСТЕМНАЯ ИНФОРМАЦИЯ")

        # BIOS
        bios_info = get_bios_info()
        print(Fore.GREEN + "\n[BIOS]")
        for k, v in bios_info.items():
            print(f"{k.ljust(15)}: {v}")

        # Диски
        partitions = get_disk_partitions()
        if partitions:
            print(Fore.GREEN + "\n[ДИСКИ]")
            for disk in partitions:
                print(f"\n▬ Физический диск #{disk.get('Номер', '?')}: {disk.get('Физический диск', 'Неизвестно')}")
                print(f"  ├ Стиль раздела: {disk.get('Стиль раздела', 'Неизвестно')}")
                print(f"  └ Общий размер: {disk.get('Размер', 'Н/Д')}")

                if disk.get('Разделы'):
                    for part in disk['Разделы']:
                        print(f"    ├─ Раздел {part.get('Буква диска', 'Без буквы')}")
                        print(f"    │  ├ Файловая система: {part.get('Файловая система', 'Неизвестна')}")
                        print(f"    │  ├ Всего места: {part.get('Размер', 'Н/Д')}")
                        print(f"    │  └ Свободно: {part.get('Свободно', 'Н/Д')}")
                else:
                    print(Fore.YELLOW + "    └ Нет доступных разделов")
        else:
            print(Fore.RED + "\n[ОШИБКА] Не удалось получить информацию о дисках")

        # Информация о Windows

        windows_info = get_windows_info()
        print(Fore.GREEN + "\n[WINDOWS]")
        for k, v in windows_info.items():
            print(f"{k.ljust(15)}: {v}")

        # Информация о процессоре
        cpu_info = get_cpu_info()
        print(Fore.GREEN + "\n[ПРОЦЕССОР]")
        for k, v in cpu_info.items():
            print(f"{k.ljust(15)}: {v}")

        # Информация о видеокартах
        gpus = get_gpu_info()
        print(Fore.GREEN + "\n[ВИДЕОКАРТЫ]")
        for i, gpu in enumerate(gpus, 1):
            print(f"GPU #{i}: {gpu['Модель']} ({gpu['Память']})")

        print_header("ПРОВЕРКА БЕЗОПАСНОСТИ")
        print_status("Secure Boot", check_secure_boot())
        print_status("TPM модуль", check_tpm())
        print_status("Виртуализация", check_virtualization())
        print_status("Изоляция ядра", check_kernel_isolation())
        print_status("Защита DMA ядра", check_dma_protection())
        print_status("SmartScreen", check_smartscreen())
        print_status("Windows Defender", check_defender())
        print_status("Брандмауэр", check_firewall())

        # Проверка антивирусов
        av_list = check_installed_software(['Avast', 'Kaspersky', '360', 'McAfee'])
        print(Fore.GREEN + "\n[АНТИВИРУСЫ]")
        print(", ".join(av_list) if av_list else "Не обнаружено")

        # Проверка античитов
        ac_list = check_installed_software(['EAC', 'BattlEye', 'FACEIT', 'VANGUARD', 'ACE'])
        running_ac = check_running_processes(['EasyAntiCheat', 'BEService', 'Faceit', 'vgc', 'ACE'])
        print(Fore.GREEN + "\n[АНТИЧИТЫ]")
        print(f"Установлено: {', '.join(ac_list) if ac_list else 'Нет'}")
        print(f"Запущено: {', '.join(running_ac) if running_ac else 'Нет'}")
        input("Нажмите Enter для выхода...")
    except Exception as e:
        print(Fore.RED + f"\nОшибка: {str(e)}")
        input("Нажмите Enter для выхода...")