"""Config flow for Audiobookshelf integration."""

from __future__ import annotations

import logging

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from aiohttp import ClientSession
from homeassistant import config_entries
from homeassistant.const import CONF_SCAN_INTERVAL, CONF_URL, CONF_TOKEN
from aioaudiobookshelf import SessionConfiguration, LoginError, get_user_client_by_token

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def validate_config(data: dict[str, str]) -> dict:
    """Validate the config entries."""
    errors = {}
    if not bool(data[CONF_URL]):
        errors[CONF_URL] = "url_invalid"
    if CONF_TOKEN not in data:
        errors[CONF_URL] = "api_key_invalid"
    if not data[CONF_URL].startswith(("http://", "https://")):
        errors[CONF_URL] = "url_protocol_missing"
    if not bool(data[CONF_SCAN_INTERVAL]):
        errors[CONF_SCAN_INTERVAL] = "scan_interval_invalid"
    return errors


async def verify_config(data: dict[str, str]) -> dict:
    """Verify the configuration by testing the API connection."""
    try:
        async with ClientSession() as session:
            await get_user_client_by_token(
                session_config=SessionConfiguration(
                    session=session,
                    url=data[CONF_URL],
                    token=data[CONF_TOKEN],
                    logger=_LOGGER,
                    pagination_items_per_page=30,
                ),
            )
        return {}
    except LoginError:
        return {"base": "api_auth_error"}


class AudiobookshelfConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Audiobookshelf."""

    VERSION = 2

    async def async_step_user(
        self, user_input: dict[str, str] | None = None
    ):
        """Handle the user step."""
        errors = {}

        if user_input is not None:
            errors.update(validate_config(user_input))
            if not errors:
                errors.update(await verify_config(user_input))
            if errors:
                return self.async_show_form(
                    step_id="user",
                    data_schema=vol.Schema(
                        {
                            vol.Required(
                                CONF_URL, default=user_input.get(CONF_URL, "")
                            ): str,
                            vol.Required(
                                CONF_TOKEN, default=user_input.get(CONF_TOKEN, "")
                            ): str,
                            vol.Optional(
                                CONF_SCAN_INTERVAL,
                                default=user_input.get(CONF_SCAN_INTERVAL, 300),
                            ): cv.positive_int,
                        }
                    ),
                    errors=errors,
                )

            return self.async_create_entry(
                title="Audiobookshelf",
                unique_id="Audiobookshelf",
                data={
                    CONF_URL: user_input[CONF_URL],
                    CONF_TOKEN: user_input[CONF_TOKEN],
                    CONF_SCAN_INTERVAL: user_input.get(CONF_SCAN_INTERVAL, 300),
                },
            )

        # Show the form to the user
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_URL): str,
                    vol.Required(CONF_TOKEN): str,
                    vol.Optional(CONF_SCAN_INTERVAL, default=300): cv.positive_int,
                }
            ),
            errors=errors,
        )
