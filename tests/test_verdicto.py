"""Regresion: un resultado INCONCLUSO (codigo interno 100) no debe contarse
como vulnerable.

Antes, la rama de 100 reasignaba paths[vector]=200 y los recolectores contaban
200/500 como VULNERABLE, convirtiendo lo no concluyente en un falso positivo.
"""
import inspect
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import panterjboss as P  # noqa: E402


def test_inconcluso_no_es_vulnerable():
    assert P._vector_vulnerable(100) is False


def test_200_y_500_son_vulnerables():
    assert P._vector_vulnerable(200) is True
    assert P._vector_vulnerable(500) is True


def test_otros_codigos_no_vulnerables():
    for c in (0, 110, 301, 302, 403, 404, 505):
        assert P._vector_vulnerable(c) is False, f"{c} no deberia ser vulnerable"


def test_session_data_preserva_inconclusos():
    assert "inconclusos" in P.session_data


def test_check_vul_no_promueve_inconcluso_a_200():
    src = inspect.getsource(P.check_vul)
    m = re.search(r"==\s*100\s*:(.*?)(?:\n\s*elif |\n\s*else:|\n\s*except)", src, re.S)
    assert m, "no se encontro la rama de inconcluso (100)"
    assert "= 200" not in m.group(1), "la rama 100 no debe promover el estado a 200"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
