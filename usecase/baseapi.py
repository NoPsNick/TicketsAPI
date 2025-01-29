import requests

class BaseAPI:
    BASE_URL = "http://localhost:8000/apis/"

    def __init__(self, token=None):
        """
        Inicializa a classe com headers e token.
        """
        self.token = token
        self.headers = {"Authorization": f"Bearer {self.token}"} if token else {}

    def _build_url(self, endpoint: str) -> str:
        """
        Constrói a URL completa com base no endpoint fornecido.
        """
        return f"{self.BASE_URL}{endpoint}"

    def get(self, endpoint, params=None):
        response = requests.get(self._build_url(endpoint), headers=self.headers, params=params)
        return self._handle_response(response)

    def post(self, endpoint, data=None):
        response = requests.post(self._build_url(endpoint), headers=self.headers, json=data)
        return self._handle_response(response)

    def delete(self, endpoint):
        response = requests.delete(self._build_url(endpoint), headers=self.headers)
        return self._handle_response(response)

    @staticmethod
    def _handle_response(response) -> list[dict] | dict:
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            return {"error": str(e), "status": response.status_code, "content": response.text}
