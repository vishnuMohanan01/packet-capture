from scapy.sendrecv import AsyncSniffer

from .flow_session import generate_session_class


def create_sniffer(
    input_interface, output_mode, output_file, url_model=None
):
    assert (input_interface is None)

    new_flow_session = generate_session_class(output_mode, output_file, url_model)

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=new_flow_session,
        store=False,
        count=0
    )


def main():
    input_interface = None
    output_mode = None
    output = None
    url_model = None

    sniffer = create_sniffer(
        input_interface,
        output_mode,
        output,
        url_model,
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == "__main__":
    main()
