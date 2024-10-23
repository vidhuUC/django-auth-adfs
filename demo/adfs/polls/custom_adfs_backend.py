import logging
from django_auth_adfs.backend import AdfsBaseBackend, AdfsAuthCodeBackend
from django_auth_adfs.config import provider_config, settings
from django.core.exceptions import PermissionDenied

logger = logging.getLogger("django_auth_adfs")


class CustomAdfsBackend(AdfsBaseBackend):
    def get_group_memberships_from_ms_graph(self, obo_access_token):
        """
         Looks up a user's group membership from the MS Graph API, handling pagination.

         Args:
        obo_access_token (str): Access token obtained from the OBO authorization endpoint

        Returns:
        claim_groups (list): List of the user's group memberships
        """

        graph_url = (
            "https://{}/v1.0/me/transitiveMemberOf/microsoft.graph.group".format(
                provider_config.msgraph_endpoint
            )
        )
        headers = {"Authorization": "Bearer {}".format(obo_access_token)}
        headers["ConsistencyLevel"] = "eventual"

        claim_groups = []
        next_link = None

        while True:
            if next_link:
                url = next_link
                params = None
            else:
                url = graph_url
                params = {"$select": "id,displayName", "$top": 999}

            response = provider_config.session.get(
                url, params=params, headers=headers, timeout=settings.TIMEOUT
            )

            # 200 = valid token received
            # 400 = 'something' is wrong in our request
            if response.status_code in [400, 401]:
                logger.error(
                    "MS Graph server returned an error: %s", response.json()["message"]
                )
                raise PermissionDenied

            if response.status_code != 200:
                logger.error(
                    "Unexpected MS Graph response: %s", response.content.decode()
                )
                raise PermissionDenied

            data = response.json()

            for group_data in data.get("value", []):
                if group_data["displayName"] is None:
                    logger.error(
                        "The application does not have the required permission to read user groups from "
                        "MS Graph (GroupMember.Read.All)"
                    )
                    raise PermissionDenied
                claim_groups.append(group_data["displayName"])

            next_link = data.get("@odata.nextLink")
            if not next_link:
                break

        return claim_groups


class CustomAdfsAuthCodeBackend(CustomAdfsBackend, AdfsAuthCodeBackend):
    pass
