import paramiko
import ftplib
from paramiko.auth_handler import AuthenticationException, SSHException
import logging
import re
from datetime import datetime, timedelta
from encriptor import key_create, key_write, file_decrypt, key_load, file_encrypt

class RemoteClient:

    def __init__(self, ipaddr, username, password):
        self.ipaddr = ipaddr
        self.username = username
        self.password = password
        self.client = None
        self.conn = None

    def connection(self):
        if self.conn is None:
            try:
                self.client = paramiko.SSHClient()
                self.client.load_system_host_keys()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(
                    self.ipaddr,
                    username=self.username,
                    password=self.password,
                    look_for_keys=False
                )
            except AuthenticationException as error:
                logging.error("autenticacion fallida, vuelva a intentar \n error es {}".format(error))
                raise error
        return self.client

    def disconnect(self):
        if self.client:
            self.client.close()

    def execute_unix_commands(self, command):
        self.conn = self.connection()
        stdin, stdout, stderr = self.conn.exec_command(command)
        stdout.channel.recv_exit_status()
        response = stdout.readlines()
        return response

    def get_alias_from_nodefind(self, output_list):
        string_aux = ""
        if len(output_list) == 0:
            return "Alias no encontrado"
        elif re.search("    Aliases:\n",output_list[0]):
            return "sin alias configurada"
        else:
            string_aux = output_list[0].replace("\n",'')
            string_aux = string_aux.replace('    Aliases: ','')
            return string_aux

    def eval_wwpn_exist_in_alias(self, alishow_output, wwpn_string):
        alishow_aux = ''.join(alishow_output)
        wwpn_aux = wwpn_string.replace("\n",'')
        if re.search(wwpn_aux,alishow_aux):
            return True
        else:
            return False

    def create_report_file(self, sansw_name, report_list):
        date = datetime.today()
        string_date = date.strftime('%Y-%m-%d-%H.%M.%S')
        f = open("aliadd_report_{}_{}.csv".format(sansw_name, string_date), "w+")
        f.write("date time, sansw_name, hostname, wwn, wwpn, alias, accion\n")
        for i in report_list:
            f.write("{}\n".format(i))
        f.close()

# the green button in the gutter to run the script.
if __name__ == '__main__':
    output_list = []
    sansw_list = []
    ftp_list = []
    loaded_key = key_load('mykey.key')
    #header = "date time, sansw_name, wwn, wwpn, alias, accion
    report_list = []
    sansw_file = open("sansw.conf")
    f = open("hosts_wwns.conf")
    list_f = []
    for i in f:
        list_f.append(i.split(';'))

    for i in sansw_file.split('\n'):
        if i != '':
            sansw_list.append(i.split(';'))

    for i in sansw_list:
        sansw_name = i[0]
        user = i[1]
        passwd = i[2]
        ip_addr = i[3]
        cfgname = i[4]
        date = datetime.today()
        string_date = date.strftime('%Y-%m-%d-%H.%M.%S')
        remote = RemoteClient(ip_addr, user, passwd)
        remote.connection()
        for value in list_f:
            output_list = remote.execute_unix_commands("nodefind {} | grep -i alias".format(value[1]))
            alias_from_nodefind_output = remote.get_alias_from_nodefind(output_list)
            if alias_from_nodefind_output == 'Alias no encontrado':
                print("{},{},{},{},{},no se ejecua ninguna accion".format(string_date,sansw_name,value[0],value[1],value[2].replace("\n",''),alias_from_nodefind_output))
                report_list.append("{},{},{},{},{},no se ejecua ninguna accion".format(string_date,sansw_name,value[0],value[1],value[2].replace("\n",''),alias_from_nodefind_output))
            elif alias_from_nodefind_output == 'sin alias configurada':
                print("{},{},{},{},{},no se ejecua ninguna accion".format(string_date,sansw_name,value[0],value[1],value[2].replace("\n",''),alias_from_nodefind_output))
                report_list.append("{},{},{},{},{},no se ejecua ninguna accion".format(string_date,sansw_name,value[0],value[1],value[2].replace("\n",''),alias_from_nodefind_output))
            else:
                output_list = remote.execute_unix_commands("alishow {}".format(alias_from_nodefind_output))
                if remote.eval_wwpn_exist_in_alias(output_list, value[2]):
                    print("{},{},{},{},{},la wwpn ya se encuentra agregada en el alias".format(string_date,sansw_name,value[0],value[1],value[2].replace("\n",''),alias_from_nodefind_output))
                    report_list.append("{},{},{},{},{},la wwpn ya se encuentra agregada en el alias".format(string_date,sansw_name,value[0],value[1],value[2].replace("\n",''),alias_from_nodefind_output))
                else:
                    print("{},{},{},{},{},Se ejecuta: aliadd {},{}".format(string_date,sansw_name,value[0],value[1],value[2].replace("\n",''),alias_from_nodefind_output,alias_from_nodefind_output,value[2].replace("\n",'')))
                    print(remote.execute_unix_commands("aliadd {},{}".format(alias_from_nodefind_output,value[2].replace("\n",''))))
                    report_list.append("{},{},{},{},{},Se ejecuta: aliadd {},{}".format(string_date,sansw_name,value[0],value[1],value[2].replace("\n",''),alias_from_nodefind_output,alias_from_nodefind_output,value[2].replace("\n",'')))

        remote.create_report_file(sansw_name, report_list)
        print("termina ejecucion en {}, puede revisar el log de la ejecución en la raiz del proyecto, ¿desea grabar la configuración? S/N ".format(sansw_name))
        save_global_conf = input()
        if save_global_conf == 'S':
            print("Se ejecuta cfgsave y cfgenable {}".format(cfgname))
            print(remote.execute_unix_commands("cfgsave -f"))
#            print(remote.execute_unix_commands("cfgenable {} -f").format(cfgname))
        else:
            print("No se ejecuta grabar")
        remote.disconnect()