from baseapi import BaseAPI


class LoginStateError(Exception):
    """Exceção personalizada para erros de estado de login."""


class Manager(BaseAPI):
    def __init__(self, token=None):
        super().__init__(token)

    def _request(self, method: str, endpoint: str, data=None, params=None):
        """
        Método interno para simplificar chamadas.
        """
        methods = {
            "POST": lambda: self.post(endpoint, data),
            "GET": lambda: self.get(endpoint, params),
            "DELETE": lambda: self.delete(endpoint)
        }

        if method not in methods:
            raise ValueError(f"Método {method} não suportado.")

        return methods[method]()

    def _set_auth_header(self, access_token: str):
        """Set the Authorization header."""
        self.headers.update({"Authorization": f"Bearer {access_token}"})

    @staticmethod
    def _format_receivers(receivers: int | str | list[int]) -> list[int]:
        if isinstance(receivers, str):
            receivers = [int(x) for x in receivers.replace(" ", "").split(",")]
        elif isinstance(receivers, int):
            receivers = [receivers]
        return receivers

    def login(self, username: str, password: str) -> dict[str, str]:
        """
        Efetua o login do usuário.
        :param username: Nome de usuário.
        :param password: Senha do usuário.
        :return: Access e Refresh token.
        """
        return self._request("POST", "login/", data={"username": username, "password": password})

    def register(self, username: str, password: str, email: str) -> dict[str, str]:
        """
        Efetua o registro do usuário.
        :param username: Nome de usuário.
        :param password: Senha do usuário.
        :param email: E-mail do usuário.
        :return: Mensagem.
        """
        return self._request("POST",
                             "registrar/",
                             data={"username": username, "password": password, "email": email})

    def logout(self, access_token, refresh_token) -> dict[str, str]:
        """
        Efetua o logout e adiciona o refresh_token na black list.
        :param access_token: Para a autenticação.
        :param refresh_token: Token de refresh válido.
        :return: Mensagem.
        """

        self._set_auth_header(access_token)
        return self._request("POST", "logout/", data={"refresh": refresh_token})

    def refresh_token(self, refresh_token) -> dict[str, str]:
        """
        Renova o access token usando o refresh token.
        :param refresh_token: Token de refresh válido.
        :return: Novo access token.
        """
        return self._request("POST", "token/refresh/", data={"refresh": refresh_token})

    def get_users(self, access_token) -> list[dict[str, str|object]]:
        """
        Pegar a lista de todos os usuários.
        :param access_token: Token de acesso válido.
        :return: Lista de usuários.
        """
        self._set_auth_header(access_token)
        return self._request("GET", "usuarios/")

    def get_user(self, access_token, username) -> dict[str, str|object]:
        """
        Pegar um usuário em específico.
        :param access_token: Token de acesso válido.
        :param username: Username do usuário.
        :return: Usuário.
        """
        self._set_auth_header(access_token)
        return self._request("GET", f"usuarios/buscar/?username={username}")

    def change_user(self, access_token, user_id: int, new_sector_id: int = None, is_staff: bool = None
                    ) -> dict[str, str]:
        """
        Pegar a lista de todos os usuários.
        :param access_token: Token de acesso válido.
        :param user_id: ID do usuário que será alterado.
        :param new_sector_id: Alterar o setor do usuário. (Opcional, requer permissão de staff, 0 remove
         o setor do usuário)
        :param is_staff: Altera se o usuário é staff ou não. (Opcional, requer permissão de superusuário)
        :return: Mensagem.
        """
        self._set_auth_header(access_token)
        return self._request("POST", f"usuarios/alterar/{user_id}/",
                             data={key: value for key, value in {
                                 "new_sector_id": new_sector_id,
                                 "is_staff": is_staff
                             }.items() if value is not None}
                             )

    def get_sent_tickets(self, access_token) -> list[dict[str, str|object]]:
        """
        Pegar a lista de chamados ENVIADOS pelo usuário.
        :param access_token: Token de acesso válido.
        :return: Lista de chamados ENVIADOS pelo usuário.
        """
        self._set_auth_header(access_token)
        return self._request("GET", "chamados/enviados/")

    def get_received_tickets(self, access_token) -> list[dict[str, str|object]]:
        """
        Pegar a lista de chamados RECEBIDOS pelo usuário.
        :param access_token: Token de acesso válido.
        :return: Lista de chamados RECEBIDOS pelo usuário.
        """
        self._set_auth_header(access_token)
        return self._request("GET", "chamados/recebidos/")

    def get_tickets_responses(self, access_token, ticket_id: int) -> list[dict[str, str|object]]:
        """
        Pegar as respostas de um chamado.
        :param access_token: Token de acesso válido.
        :param ticket_id: ID do chamado.
        :return: As respostas de um chamado.
        """
        self._set_auth_header(access_token)
        return self._request("GET", f"chamados/respostas/{ticket_id}/")

    def create_ticket(self, access_token, title: str, description: str, receivers: str | list) -> dict[str, str|object]:
        """
        Criar um chamado.
        :param access_token: Token de acesso válido.
        :param title: Título do chamado.
        :param description: Descrição do chamado.
        :param receivers: IDs dos usuários que irão receber o chamado.
        :return: O chamado criado.
        """
        self._set_auth_header(access_token)
        receivers = self._format_receivers(receivers)
        return self._request("POST", "chamados/criar/",
                             data={"title": title,
                                   "description": description,
                                   "receivers": receivers})

    def create_ticket_response(self, access_token, ticket_id: int, content: str) -> dict[str, str|object]:
        """
        Criar uma resposta para um chamado.
        :param access_token: Token de acesso válido.
        :param ticket_id: ID do chamado.
        :param content: Conteúdo da resposta.
        :return: A resposta criada.
        """
        self._set_auth_header(access_token)
        return self._request("POST", f"chamados/responder/{ticket_id}/",
                             data={"content": content})

    def change_ticket_status(self, access_token, ticket_id: int, new_status: str) -> dict[str, str]:
        """
        Alterar o estado do chamado.
        :param access_token: Token de acesso válido.
        :param ticket_id: ID do chamado.
        :param new_status: Novo estado do ticket.
        :return: Mensagem.
        """
        self._set_auth_header(access_token)
        return self._request("POST", f"chamados/status/{ticket_id}/",
                             data={"new_status": new_status})

    def delete_ticket(self, access_token, ticket_id: int) -> dict[str, str]:
        """
        Remover um chamado.
        :param access_token: Token de acesso válido.
        :param ticket_id: ID do chamado.
        :return: Mensagem.
        """
        self._set_auth_header(access_token)
        return self._request("DELETE", f"chamados/remover/{ticket_id}/", )

    def get_sectors(self, access_token) -> list[dict[str, str|object]]:
        """
        Pegar os setores disponíveis.
        :param access_token: Token de acesso válido.
        :return: Lista dos setores.
        """
        self._set_auth_header(access_token)
        return self._request("GET", "setores/")

    def create_sector(self, access_token, name: str, description: str, leader_id: int = None
                      ) -> dict[str, str|object]:
        """
        Criar um setor.
        :param access_token: Token de acesso válido.
        :param name: Nome do setor.
        :param description: Descrição do setor.
        :param leader_id: Usuário líder do setor.
        :return: Setor criado.
        """
        self._set_auth_header(access_token)
        return self._request("POST", "setores/criar/",
                             data={"name": name, "description": description, "leader_id": leader_id})

    def delete_sector(self, access_token, sector_id: int) -> dict[str, str]:
        """
        Remover um setor.
        :param access_token: Token de acesso válido
        :param sector_id: ID do setor.
        :return: Mensagem.
        """
        self._set_auth_header(access_token)
        return self._request("DELETE", f"setores/remover/{sector_id}/", )

    def change_sector(self, access_token, sector_id: int, name: str = None, description: str = None,
                      leader_id: int = None) -> dict[str, str]:
        """
        Alterar um setor.
        :param access_token: Token de acesso válido.
        :param sector_id: ID do setor.
        :param name: Novo nome do setor. Deixar como None não altera o nome.
        :param description: Nova descrição do setor. Deixar como None não altera a descrição.
        :param leader_id:  Novo líder. Deixar como None não remove o Líder atual, porém se colocar 0,
         remove o Líder atual.
        :return: Mensagem.
        """
        self._set_auth_header(access_token)
        return self._request("POST", f"setores/alterar/{sector_id}/",
                             data={"name": name,
                                   "description": description,
                                   'leader_id': leader_id})


class User:
    def __init__(self):
        self.username = None
        self.identification = None
        self.access_token = None
        self.refresh_token = None
        self.manager = Manager()

    def _store_tokens(self, response):
        self.access_token = response["access"]
        self.refresh_token = response["refresh"]

    def _get_users(self):
        users = self.manager.get_users(access_token=self.access_token)
        return users

    def _get_user(self, username):
        user = self.manager.get_user(access_token=self.access_token, username=username)
        return user

    def _store_user_infos(self, username):
        self._verify_login()
        user = self._get_user(username)
        self.username = user.get("username")
        self.identification = int(user.get("id"))

    def _clear_tokens(self):
        self.access_token = self.refresh_token = self.username = self.identification = None

    def _verify_login(self, logged=True, login=False):
        """
        Verifica o estado do login com base nos tokens.

        Parâmetros:
        - logged (bool): Verifica se o usuário já está logado (True) ou deslogado (False).
        - login (bool): Indica se a verificação é para uma tentativa de login.

        Exceções:
        - LoginStateError: Se o estado do login não atender aos critérios fornecidos.
        """
        is_logged = bool(self.access_token and self.refresh_token)

        if logged and not is_logged and not login:
            raise LoginStateError("Usuário deslogado.")
        elif not logged and not is_logged and not login:
            raise LoginStateError("Usuário já está deslogado.")
        elif is_logged and login:
            raise LoginStateError("Usuário já está logado.")

    def login(self, username: str, password: str):
        """
        Realiza o login, armazenando os tokens de acesso e atualização.
        """
        self._verify_login(login=True)
        response = self.manager.login(username, password)
        self._store_tokens(response)
        self._store_user_infos(username)
        return {"message": f"Usuário {self.username} #{self.identification} logado com sucesso!"}

    def logout(self):
        """
        Realiza o logout, invalidando os tokens e limpando dados do usuário.
        """
        self._verify_login(logged=False)
        self.manager.logout(self.access_token, self.refresh_token)
        self._clear_tokens()
        return {"message": "Deslogado com sucesso!"}

    def register(self, username: str, password: str, email: str):
        response = self.manager.register(username, password, email)
        return response

    def refresh_access_token(self):
        """
        Renova o access token usando o refresh token.
        """
        response = self.manager.refresh_token(self.refresh_token)
        self.access_token = response["access"]
        return {"message": "Access token renovado com sucesso!"}

    def get_users_list(self):
        """
        Pegar a lista de usuários
        """
        self._verify_login()
        return self._get_users()

    def change_user(self, user_id: int, new_sector_id: int = None, is_staff: bool = None):
        """
        Alterar um usuário.
        """
        self._verify_login()
        return self.manager.change_user(self.access_token, user_id, new_sector_id, is_staff)

    def get_sent_tickets(self):
        """
        Pegar os chamados enviados.
        """
        self._verify_login()
        return self.manager.get_sent_tickets(self.access_token)

    def get_received_tickets(self):
        """
        Pegar os chamados recebidos.
        """
        self._verify_login()
        return self.manager.get_received_tickets(self.access_token)

    def get_tickets_responses(self, ticket_id: int):
        """
        Pegar as respostas de um chamado.
        """
        self._verify_login()
        return self.manager.get_tickets_responses(self.access_token, ticket_id)

    def create_ticket(self, title: str, description: str, receivers: int | str | list):
        """
        Criar um chamado.
        """
        self._verify_login()
        return self.manager.create_ticket(self.access_token, title, description, receivers)

    def create_ticket_response(self, ticket_id: int, content: str):
        """
        Criar a resposta de um chamado.
        """
        self._verify_login()
        return self.manager.create_ticket_response(self.access_token, ticket_id, content)

    def change_ticket_status(self, ticket_id: int, new_status: str):
        """
        Alterar o estado de um chamado.
        """
        self._verify_login()
        return self.manager.change_ticket_status(self.access_token, ticket_id, new_status)

    def delete_ticket(self, ticket_id: int):
        """
        Remover um chamado.
        """
        self._verify_login()
        return self.manager.delete_ticket(self.access_token, ticket_id)

    def get_sectors(self):
        """
        Pegar setores.
        """
        self._verify_login()
        return self.manager.get_sectors(self.access_token)

    def create_sector(self, name: str, description: str, leader_id: int = None):
        """
        Criar setores.
        """
        self._verify_login()
        return self.manager.create_sector(self.access_token, name, description, leader_id)

    def delete_sector(self, sector_id: int):
        """
        Remover um setor.
        """
        self._verify_login()
        return self.manager.delete_sector(self.access_token, sector_id)

    def change_sector(self, sector_id: int, name: str = None, description: str = None, leader_id: int = None):
        """
        Alterar um setor.
        """
        self._verify_login()
        return self.manager.change_sector(self.access_token, sector_id, name, description, leader_id)


if __name__ == "__main__":
    user_adm = User()
    print(user_adm.login(username='admin', password='admin'))
    print(user_adm.get_users_list())
    print(user_adm.get_sectors())
    print(user_adm.get_sent_tickets())
    print(user_adm.get_received_tickets(), "*********")
    print(user_adm.get_tickets_responses(1))
    print(user_adm.change_ticket_status(1, "pendente"))

    normal_user = User()
    print(normal_user.login(username='normal', password='abcd1234'))
    print(normal_user.get_users_list())
    print(normal_user.get_received_tickets())
    print(normal_user.get_sent_tickets())
