
import re
import wmi
import winreg
import subprocess
import os
import ctypes
import sys
from datetime import datetime
from colorama import Fore, init
import json
import logging

# Инициализация цветного вывода
init(autoreset=True)

# Настройка логирования
logging.basicConfig(
    filename='system_check.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def run_as_admin():
    """Перезапуск скрипта с правами администратора"""
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            sys.exit(0)
    except Exception as e:
        logging.error(f"Ошибка при запросе прав администратора: {e}")
        sys.exit(1)

def print_header(text):
    """Вывод заголовка с оформлением"""
    print(Fore.CYAN + "\n" + "=" * 50)
    print(Fore.YELLOW + f" {text}")
    print(Fore.CYAN + "=" * 50)

def print_headers():
    """Вывод кастомного заголовка с версией и автором"""
    title = "GAMEBREAKER CHECKER - СИСТЕМНАЯ ИНФОРМАЦИЯ"
    version_info = "v 1.0 by Voldemort1337"

    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.RED + f" {title.center(58)}")
    print(Fore.CYAN + "-" * 60)
    print(Fore.YELLOW + f" {version_info.rjust(57)} ")
    print(Fore.CYAN + "=" * 60)


def print_status(item, status):
    """Форматированный вывод статусов"""
    color = Fore.GREEN if status in ["Да", "Включен", "Активен"] else Fore.RED if status in ["Нет", "Выключен",
                                                                                             "Неактивен"] else Fore.WHITE
    print(Fore.WHITE + f"{item.ljust(35)}: {color}{status}")


def format_bios_date(bios_date):
    """Преобразование даты BIOS в читаемый формат"""
    try:
        return datetime.strptime(bios_date.split('.')[0], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        logging.error(f"Ошибка формата даты BIOS: {e}")
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
        logging.error(f"Ошибка получения информации BIOS: {e}")
        return {"Ошибка": str(e)}


def check_partition_style_powershell():
    """Получение стиля разделов через PowerShell"""
    try:
        output = subprocess.check_output(
            ["powershell", "Get-Disk | Select-Object Number, PartitionStyle | ConvertTo-Json"],
            text=True,
            stderr=subprocess.STDOUT,
            shell=True
        ).strip()

        disks = json.loads(output) if output else []

        if isinstance(disks, dict):
            return {disks["Number"]: disks["PartitionStyle"]}
        if isinstance(disks, list):
            return {disk["Number"]: disk["PartitionStyle"] for disk in disks}
        return {}

    except Exception as e:
        output = locals().get('output', '')
        logging.error(f"Ошибка PowerShell: {e}\nВывод: {output}")
        return {}


def format_size(size_bytes):
    """Форматирование размера в читаемый вид"""
    try:
        return f"{int(int(size_bytes) // (1024 ** 3))} GB" if size_bytes else "0 GB"
    except Exception as e:
        logging.error(f"Ошибка форматирования размера: {e}")
        return "Н/Д"


def get_disk_partitions():
    """Получение информации о дисках и разделах"""
    try:
        result = []
        c = wmi.WMI()
        ps_style = check_partition_style_powershell()

        for physical_disk in c.Win32_DiskDrive():
            disk_info = {
                "Физический диск": getattr(physical_disk, "Caption", "Неизвестно"),
                "Номер": int(getattr(physical_disk, "Index", -1)),
                "Стиль раздела": "Неизвестно",
                "Размер": format_size(getattr(physical_disk, "Size", 0)),
                "Разделы": []
            }

            try:
                disk_info["Стиль раздела"] = ps_style.get(
                    disk_info["Номер"],
                    {1: "MBR", 2: "GPT"}.get(
                        int(getattr(physical_disk, "PartitionStyle", 0)),
                        "Неизвестно"
                    )
                )
            except Exception as e:
                logging.error(f"Ошибка определения стиля раздела: {e}")

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
                logging.error(f"Ошибка получения разделов: {e}")

            result.append(disk_info)
        return result

    except Exception as e:
        logging.error(f"Критическая ошибка дисков: {e}")
        return []


def get_registry_value(key_path, value_name):
    """Получение значения из реестра"""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value
    except FileNotFoundError:
        return None
    except Exception as e:
        logging.error(f"Ошибка реестра {key_path}: {e}")
        return None


def get_windows_info():
    """Получение информации о Windows"""
    try:
        c = wmi.WMI()
        os_info = c.Win32_OperatingSystem()[0]

        return {
            "Версия": getattr(os_info, 'Caption', 'Неизвестно'),
            "Сборка": getattr(os_info, 'BuildNumber', 'Н/Д'),
            "Архитектура": getattr(os_info, 'OSArchitecture', 'Н/Д'),
            "Лицензия": "Активирована" if getattr(os_info, 'LicenseStatus', 0) == 1 else "Не активирована",
            "Дата установки": datetime.strptime(
                os_info.InstallDate.split('.')[0],
                "%Y%m%d%H%M%S"
            ).strftime("%Y-%m-%d %H:%M:%S") if hasattr(os_info, 'InstallDate') else "Н/Д"
        }
    except Exception as e:
        logging.error(f"Ошибка получения информации ОС: {e}")
        return {"Ошибка": str(e)}


def get_cpu_info(virtualization_status=None):
    """Получение информации о процессоре с синхронизированной проверкой виртуализации"""
    cpu_info = {
        "Модель": "Неизвестно",
        "Производитель": "Н/Д",
        "Ядра": "Н/Д",
        "Потоки": "Н/Д",
        "Базовая частота": "Н/Д",
        "Кэш L2": "Н/Д",
        "Кэш L3": "Н/Д",
        "Виртуализация": "Неизвестно"
    }

    try:
        # Основная информация через WMI
        try:
            c = wmi.WMI()
            processor = c.Win32_Processor()[0]

            cpu_info.update({
                "Модель": getattr(processor, 'Name', 'Неизвестно').strip(),
                "Ядра": getattr(processor, 'NumberOfCores', 'Н/Д'),
                "Потоки": getattr(processor, 'NumberOfLogicalProcessors', 'Н/Д'),
                "Базовая частота": f"{getattr(processor, 'MaxClockSpeed', 0)} МГц",
            })

        except Exception as wmi_error:
            logging.error(f"Ошибка WMI: {wmi_error}")

        # Синхронизация статуса виртуализации
        if virtualization_status is not None:
            cpu_info["Виртуализация"] = virtualization_status
        else:
            try:
                # Используем общий метод проверки
                from ctypes import windll
                virt_status = "Включена" if windll.kernel32.IsProcessorFeaturePresent(22) else "Выключена"
                cpu_info["Виртуализация"] = virt_status
            except Exception as virt_error:
                logging.warning(f"Ошибка проверки виртуализации: {virt_error}")

        # Дополнительная информация через PowerShell
        try:
            ps_output = subprocess.check_output(
                ["powershell", "-Command", "Get-WmiObject Win32_Processor | Select-Object *"],
                text=True,
                stderr=subprocess.STDOUT,
                shell=True
            )

            # Парсинг кэша
            l2_cache = re.search(r"L2CacheSize\s*:\s*(\d+)", ps_output)
            l3_cache = re.search(r"L3CacheSize\s*:\s*(\d+)", ps_output)

            if l2_cache:
                size = int(l2_cache.group(1))
                cpu_info["Кэш L2"] = f"{size} КБ" if size < 1024 else f"{size/1024:.1f} МБ"

            if l3_cache:
                size = int(l3_cache.group(1))
                cpu_info["Кэш L3"] = f"{size} КБ" if size < 1024 else f"{size/1024:.1f} МБ"

        except Exception as ps_error:
            logging.warning(f"Ошибка PowerShell: {ps_error}")

    except Exception as e:
        logging.error(f"Общая ошибка: {e}")

    return cpu_info


def check_secure_boot():
    """Проверка Secure Boot"""
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "Confirm-SecureBootUEFI"],
            text=True,
            stderr=subprocess.STDOUT
        ).strip().lower()
        return "Да" if output == "true" else "Нет"
    except subprocess.CalledProcessError:
        return "Не поддерживается"
    except Exception as e:
        logging.error(f"Ошибка Secure Boot: {e}")
        return "Ошибка"


def check_tpm():
    """Проверка TPM модуля с многоуровневой диагностикой"""
    try:
        # Метод 1: Проверка через WMI
        try:
            c = wmi.WMI()
            tpm_list = c.Win32_Tpm()
            if tpm_list:
                tpm = tpm_list[0]
                activated = getattr(tpm, 'IsActivated_InitialValue', False)
                enabled = getattr(tpm, 'IsEnabled_InitialValue', False)
                if activated and enabled:
                    return "Да"
        except Exception as wmi_error:
            logging.warning(f"WMI TPM check failed: {wmi_error}")

        # Метод 2: Проверка через реестр
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\TPM") as key:
                device_name = winreg.QueryValueEx(key, "DeviceName")[0]
                if device_name:
                    return "Да (обнаружен в реестре)"
        except FileNotFoundError:
            pass
        except Exception as reg_error:
            logging.warning(f"Registry TPM check failed: {reg_error}")

        # Метод 3: Проверка через PowerShell
        try:
            ps_output = subprocess.check_output(
                ["powershell", "-Command", "$tpm = Get-Tpm; $tpm.TpmPresent"],
                text=True,
                stderr=subprocess.STDOUT,
                shell=True
            ).strip()

            if ps_output.lower() == "true":
                return "Да"
            elif ps_output.lower() == "false":
                return "Нет"
        except Exception as ps_error:
            logging.warning(f"PowerShell TPM check failed: {ps_error}")

        # Метод 4: Проверка через systeminfo
        try:
            output = subprocess.check_output(
                "systeminfo",
                text=True,
                stderr=subprocess.STDOUT,
                shell=True
            )
            if "TPM" in output and "2.0" in output:
                return "Да (TPM 2.0)"
        except Exception as sys_error:
            logging.warning(f"Systeminfo check failed: {sys_error}")

        return "Нет"

    except Exception as e:
        logging.error(f"Critical TPM check error: {e}")
        return "Ошибка проверки"


def check_virtualization():
    """Проверка виртуализации через те же методы, что и в get_cpu_info"""
    try:
        # Метод 1: WMI (как в get_cpu_info)
        try:
            c = wmi.WMI()
            processor = c.Win32_Processor()[0]
            if getattr(processor, 'VirtualizationFirmwareEnabled', False):
                return "Да"
        except Exception as wmi_error:
            logging.warning(f"WMI Error: {wmi_error}")

        # Метод 2: Реестр (аналогично get_cpu_info)
        try:
            reg_value = get_registry_value(
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                "FeatureSet"
            )
            if reg_value and (reg_value & 0x80000000):  # Проверка бита виртуализации
                return "Да"
        except Exception as reg_error:
            logging.warning(f"Registry Error: {reg_error}")

        # Метод 3: PowerShell (как в get_cpu_info)
        try:
            ps_output = subprocess.check_output(
                ["powershell", "-Command", "(Get-WmiObject Win32_Processor).VirtualizationFirmwareEnabled"],
                text=True,
                stderr=subprocess.STDOUT,
                shell=True
            ).strip()

            if ps_output.lower() in ["true", "1"]:
                return "Да"
        except Exception as ps_error:
            logging.warning(f"PowerShell Error: {ps_error}")

        # Метод 4: CPUID (как в get_cpu_info)
        try:
            from ctypes import windll
            if windll.kernel32.IsProcessorFeaturePresent(22):  # 22 = PF_VIRT_FIRMWARE_ENABLED
                return "Да"
        except Exception as cpuid_error:
            logging.warning(f"CPUID Error: {cpuid_error}")

        return "Нет"

    except Exception as e:
        logging.error(f"Critical Error: {e}")
        return "Ошибка проверки"


def check_kernel_isolation():
    """Проверка изоляции ядра"""
    try:
        value = get_registry_value(
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled"
        )
        return "Да" if value == 1 else "Нет"
    except Exception as e:
        logging.error(f"Ошибка проверки изоляции ядра: {e}")
        return "Ошибка"


def check_dma_protection():
    """Проверка DMA-защиты (возвращает Да/Нет/Ошибка)"""
    try:
        protection_found = False

        # 1. Проверка основного ключа реестра
        try:
            reg_value = get_registry_value(
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\DmaGuard",
                "Enabled"
            )
            if reg_value == 1:
                protection_found = True
        except Exception as e:
            logging.warning(f"Ошибка реестра DMA: {e}")

        # 2. Проверка через WMI
        if not protection_found:
            try:
                c = wmi.WMI()
                security_status = c.Win32_DeviceGuard()
                if security_status and getattr(security_status[0], 'DmaProtectionStatus', 0) == 1:
                    protection_found = True
            except Exception as e:
                logging.warning(f"Ошибка WMI: {e}")

        # 3. Проверка через PowerShell
        if not protection_found:
            try:
                ps_output = subprocess.check_output(
                    ["powershell", "-Command",
                     "(Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard).DmaProtectionStatus"],
                    text=True,
                    stderr=subprocess.STDOUT,
                    shell=True
                )
                if ps_output.strip() == "1":
                    protection_found = True
            except Exception as e:
                logging.warning(f"Ошибка PowerShell: {e}")

        return "Да" if protection_found else "Нет"

    except Exception as e:
        logging.error(f"Критическая ошибка проверки DMA: {e}")
        return "Ошибка"


def check_smartscreen():
    """Проверка через PowerShell"""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' | Select-Object SmartScreenEnabled"],
            capture_output=True,
            text=True,
            shell=True
        )
        output = result.stdout.lower()

        if "requireadmin" in output: return "Включен"
        if "warn" in output: return "Включен"
        if "on" in output: return "Включен"
        if "off" in output: return "Выключен"
        return "Неизвестный статус"

    except Exception as e:
        return f"Ошибка: {str(e)}"


def check_defender():
    """Проверка Windows Defender"""
    try:
        c = wmi.WMI()
        service = c.Win32_Service(Name="WinDefend")[0]
        rt_disabled = get_registry_value(
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring"
        ) or 0
        return "Активен" if service.State == "Running" and rt_disabled == 0 else "Неактивен"
    except Exception as e:
        logging.error(f"Ошибка проверки Defender: {e}")
        return "Ошибка"


def check_firewall():
    """Проверка статуса брандмауэра (возвращает Активен/Не активен/Ошибка)"""
    try:
        # Проверка базового состояния службы
        try:
            c = wmi.WMI()
            service = c.Win32_Service(Name="MpsSvc")[0]
            if service.State != "Running":
                return "Неактивен"
        except Exception as e:
            logging.warning(f"Ошибка WMI: {e}")

        # Проверка активных профилей
        try:
            ps_output = subprocess.check_output(
                ["powershell", "-Command",
                 "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'True'}) -ne $null"],
                text=True,
                stderr=subprocess.STDOUT,
                shell=True
            )
            if "True" in ps_output:
                return "Активен"
        except Exception as e:
            logging.warning(f"Ошибка PowerShell: {e}")

        # Дополнительная проверка через реестр
        try:
            domain_enabled = get_registry_value(
                r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                "EnableFirewall"
            )
            if domain_enabled == 1:
                return "Активен"
        except Exception as e:
            logging.warning(f"Ошибка реестра: {e}")

        return "Неактивен"

    except Exception as e:
        logging.error(f"Критическая ошибка: {e}")
        return "Ошибка"


def check_installed_software(keywords):
    """Поиск установленных программ по ключевым словам"""
    found = set()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        try:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            if any(kw.lower() in name.lower() for kw in keywords):
                                found.add(name)
                        except FileNotFoundError:
                            pass
                except WindowsError:
                    pass
        return list(found) if found else ["Не найдено"]
    except Exception as e:
        logging.error(f"Ошибка поиска ПО: {e}")
        return ["Ошибка"]


def check_running_processes(keywords):
    """Поиск запущенных процессов по ключевым словам"""
    found = set()
    try:
        c = wmi.WMI()
        for process in c.Win32_Process():
            if any(kw.lower() in process.Name.lower() for kw in keywords):
                found.add(process.Name)
        return list(found) if found else ["Не найдено"]
    except Exception as e:
        logging.error(f"Ошибка поиска процессов: {e}")
        return ["Ошибка"]


if __name__ == "__main__":
    run_as_admin()

    try:

        print_headers()

        # BIOS
        bios_info = get_bios_info()
        print(Fore.GREEN + "\n[BIOS]")
        for k, v in bios_info.items():
            print(f"{k.ljust(15)}: {v}")

        # Диски
        partitions = get_disk_partitions()
        print(Fore.GREEN + "\n[ДИСКИ]")
        for disk in partitions:
            print(f"\n▬ Диск #{disk.get('Номер', '?')}: {disk.get('Физический диск', 'Неизвестно')}")
            print(f"  ├ Стиль раздела: {disk.get('Стиль раздела', 'Неизвестно')}")
            print(f"  └ Размер: {disk.get('Размер', 'Н/Д')}")

            for part in disk.get('Разделы', []):
                print(f"    ├─ Раздел {part.get('Буква', 'Без буквы')}")
                print(f"    │  ├ Файловая система: {part.get('Файловая система', 'Неизвестна')}")
                print(f"    │  ├ Всего места: {part.get('Размер', 'Н/Д')}")
                print(f"    │  └ Свободно: {part.get('Свободно', 'Н/Д')}")

        # Windows
        windows_info = get_windows_info()
        print(Fore.GREEN + "\n[WINDOWS]")
        for k, v in windows_info.items():
            print(f"{k.ljust(15)}: {v}")

        # Вывод информации
        cpu_info = get_cpu_info()
        print(Fore.CYAN + "\n" + "=" * 50)
        print(Fore.YELLOW + " ХАРАКТЕРИСТИКИ ПРОЦЕССОРА")
        print(Fore.CYAN + "=" * 50)

        # Форматирование вывода
        labels = {
            "Модель": "Модель процессора",
            "Производитель": "Производитель",
            "Ядра": "Количество ядер",
            "Потоки": "Количество потоков",
            "Базовая частота": "Базовая частота",
            "Кэш L2": "Кэш второго уровня",
            "Кэш L3": "Кэш третьего уровня",
            "Виртуализация": "Виртуализация"
        }

        max_label_length = max(len(label) for label in labels.values())

        for key, label in labels.items():
            value = cpu_info.get(key, "Н/Д")
            if isinstance(value, int):
                value = str(value)
            print(Fore.WHITE + f"{label.ljust(max_label_length)} : {Fore.GREEN}{value}")

        print_header("ПРОВЕРКА БЕЗОПАСНОСТИ")
        print_status("Secure Boot", check_secure_boot())
        print_status("TPM модуль", check_tpm())
        print_status("Виртуализация", check_virtualization())
        print_status("Изоляция ядра", check_kernel_isolation())
        print_status("Защита DMA", check_dma_protection())
        print_status("SmartScreen", check_smartscreen())
        print_status("Windows Defender", check_defender())
        print_status("Брандмауэр", check_firewall())

        # Проверка ПО
        print(Fore.GREEN + "\n[АНТИВИРУСЫ]")
        av_list = check_installed_software(['Avast', 'Kaspersky', 'ESET', 'Norton', 'Dr.Web'])
        print(", ".join(av_list) if av_list else "Не обнаружено")

        print(Fore.GREEN + "\n[АНТИЧИТЫ]")
        ac_installed = check_installed_software(['EasyAntiCheat', 'BattlEye', 'FACEIT', 'VANGUARD'])
        ac_running = check_running_processes(['EasyAntiCheat', 'BEService', 'Faceit', 'vgc'])
        print(f"Установлено: {', '.join(ac_installed) if ac_installed else 'Нет'}")
        print(f"Запущено: {', '.join(ac_running) if ac_running else 'Нет'}")

        input("\nНажмите Enter для выхода...")

    except Exception as e:
        logging.error(f"Критическая ошибка: {e}")
        print(Fore.RED + f"\nПроизошла ошибка: {e}")
        input("Нажмите Enter для выхода...")