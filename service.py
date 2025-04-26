import win32serviceutil
import win32service
import win32event
import servicemanager
import time
import socket
from core.logger import setup_logging # 确保日志能写入服务可访问的位置

# 配置服务日志
logger = setup_logging(log_file='c:/path/to/your/service.log') # 需要绝对路径且服务有权限写入

class XduNetHelperService(win32serviceutil.ServiceFramework):
    _svc_name_ = "XDUNetHelperService"
    _svc_display_name_ = "XDU Network Helper Service"
    _svc_description_ = "Provides background support and privileged operations for XDU Network Resolver."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.is_running = True
        # 在这里初始化 IPC 服务端监听 (后面实现)
        # self.ipc_server = core.ipc_server.start_listening(self.handle_command)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        # 关闭 IPC 服务端
        # self.ipc_server.stop()
        logger.info("服务停止请求")

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def main(self):
        logger.info("服务启动")
        while self.is_running:
            # 主要的服务逻辑循环
            # 1. 检查 IPC 队列是否有新命令 (非阻塞)
            #    command = self.ipc_server.check_for_command()
            #    if command:
            #        self.handle_command(command)

            # 2. 执行定期的后台任务 (例如，每隔一段时间检查网络状态或更新)
            #    self.perform_periodic_tasks()

            # 等待一段时间或等待停止信号
            rc = win32event.WaitForSingleObject(self.hWaitStop, 5000) # 等待5秒
            if rc == win32event.WAIT_OBJECT_0:
                # 收到停止信号
                break
        logger.info("服务主循环退出")
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)


    # def handle_command(self, command_data):
    #     """处理从 CLI 通过 IPC 收到的命令"""
    #     command = command_data.get('command')
    #     params = command_data.get('params', {})
    #     logger.info(f"收到命令: {command} 参数: {params}")
    #     result = {'status': 'ERROR', 'message': 'Unknown command'}
    #     try:
    #         if command == 'FIX_PROXY':
    #             net_utils.fix_proxy() # 服务运行时通常有足够权限
    #             result = {'status': 'SUCCESS'}
    #         elif command == 'DISABLE_IPV6':
    #             adapter = params.get('adapter_name')
    #             if adapter:
    #                 net_utils.toggle_ipv6(adapter, enable=False)
    #                 result = {'status': 'SUCCESS'}
    #             else:
    #                 result['message'] = 'Missing adapter name'
    #         # ... 处理其他命令 ...
    #         else:
    #             logger.warning(f"收到未知命令: {command}")

    #     except Exception as e:
    #         logger.exception(f"处理命令 {command} 时出错")
    #         result['message'] = str(e)

    #     # 通过 IPC 将结果发回给客户端
    #     # self.ipc_server.send_response(command_data['client_id'], result)


    # def perform_periodic_tasks(self):
    #      """执行需要定期运行的任务"""
    #      # logger.debug("执行定期任务检查...")
    #      # 例如：core.updater.check_for_updates()
    #      pass

if __name__ == '__main__':
    # 这个 __main__ 块使得 service_installer.py 可以导入并使用这个类
    # 同时也可以直接通过命令行管理服务 (python service.py install/start/stop/remove)
     if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(XduNetHelperService)
        servicemanager.StartServiceCtrlDispatcher()
     else:
        win32serviceutil.HandleCommandLine(XduNetHelperService)
