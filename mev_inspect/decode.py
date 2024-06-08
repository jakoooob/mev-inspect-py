from typing import Dict, Optional

import eth_utils.abi
from eth_abi import decode_abi
from eth_abi.exceptions import InsufficientDataBytes, NonEmptyPaddingBytes
from hexbytes._utils import hexstr_to_bytes

from mev_inspect.schemas.abi import ABI, ABIFunctionDescription
from mev_inspect.schemas.call_data import CallData

# 0x + 8 characters
SELECTOR_LENGTH = 10


class ABIDecoder:
    def __init__(self, abi: ABI):
        self._functions_by_selector: Dict[str, ABIFunctionDescription] = {
            description.get_selector(): description
            for description in abi
            if isinstance(description, ABIFunctionDescription)
        }

    def decode(self, data: str) -> Optional[CallData]:
        selector, params = data[:SELECTOR_LENGTH], data[SELECTOR_LENGTH:]

        func = self._functions_by_selector.get(selector)

        if func is None:
            return None

        names = [input.name for input in func.inputs]
        types = [
            input.type
            if input.type != "tuple"
            else eth_utils.abi.collapse_if_tuple(input.dict())
            for input in func.inputs
        ]

        bytes_array = hexstr_to_bytes(params)

        if len(types) > 0:
            last_element_datatype = types[-1]
            if last_element_datatype != "bytes":
                pass
            else:
                # optionally pad the bytes array to 32 bytes
                last_bytes = len(hexstr_to_bytes(params)) % 32
                diff_to_32 = 32 - last_bytes
                for to_add in range(diff_to_32):
                    bytes_array += b'\x00'

        try:
            decoded = decode_abi(types, bytes_array)
        except (InsufficientDataBytes, NonEmptyPaddingBytes, OverflowError) as ex:
            print(ex)
            return None

        return CallData(
            function_name=func.name,
            function_signature=func.get_signature(),
            inputs={name: value for name, value in zip(names, decoded)},
        )
