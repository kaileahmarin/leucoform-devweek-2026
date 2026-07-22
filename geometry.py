"""Small dependency-free geometry kernel for the Leucoform companion."""

from __future__ import annotations

from dataclasses import dataclass
from math import cos, sin, sqrt

Vec3 = tuple[float, float, float]
Face = tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class Solid:
    vertices: tuple[Vec3, ...]
    faces: tuple[Face, ...]


_PHI = (1.0 + sqrt(5.0)) / 2.0
_INV_PHI = 1.0 / _PHI

# The compact integer notation uses 2 = 1/phi and 3 = phi.  This is an
# audited 32-vertex/30-face golden-rhombus model; keeping the face topology
# explicit prevents rendering-library or convex-hull drift.
_VERTEX_CODES: tuple[tuple[int, int, int], ...] = (
    (-1, 0, 3),
    (-1, 1, 1),
    (0, 2, 3),
    (0, -2, 3),
    (-1, -1, 1),
    (3, 1, 0),
    (1, 1, 1),
    (0, 3, 1),
    (1, 0, 3),
    (3, 0, 2),
    (1, -1, 1),
    (0, -3, 1),
    (-3, 0, 2),
    (-3, 1, 0),
    (-2, 3, 0),
    (2, 3, 0),
    (3, -1, 0),
    (2, -3, 0),
    (3, 0, -2),
    (0, -3, -1),
    (-2, -3, 0),
    (-3, -1, 0),
    (-3, 0, -2),
    (-1, -1, -1),
    (1, -1, -1),
    (0, -2, -3),
    (-1, 0, -3),
    (1, 0, -3),
    (1, 1, -1),
    (0, 2, -3),
    (-1, 1, -1),
    (0, 3, -1),
)

_FACES: tuple[Face, ...] = (
    (0, 2, 8, 3),
    (25, 26, 29, 27),
    (2, 7, 6, 8),
    (3, 8, 10, 11),
    (0, 1, 7, 2),
    (27, 28, 31, 29),
    (0, 3, 11, 4),
    (19, 24, 27, 25),
    (26, 29, 31, 30),
    (5, 6, 7, 15),
    (10, 11, 17, 16),
    (5, 15, 31, 28),
    (1, 7, 14, 13),
    (4, 11, 20, 21),
    (13, 14, 31, 30),
    (16, 17, 19, 24),
    (19, 20, 21, 23),
    (5, 6, 8, 9),
    (0, 1, 13, 12),
    (19, 23, 26, 25),
    (8, 9, 16, 10),
    (5, 18, 27, 28),
    (0, 4, 21, 12),
    (13, 22, 26, 30),
    (16, 18, 27, 24),
    (21, 22, 26, 23),
    (7, 14, 31, 15),
    (11, 17, 19, 20),
    (5, 9, 16, 18),
    (12, 13, 22, 21),
)


def _decode(value: int) -> float:
    if value == 2:
        return _INV_PHI
    if value == -2:
        return -_INV_PHI
    if value == 3:
        return _PHI
    if value == -3:
        return -_PHI
    return float(value)


def _decode_vertex(vertex: tuple[int, int, int]) -> Vec3:
    return _decode(vertex[0]), _decode(vertex[1]), _decode(vertex[2])


RHOMBIC_TRIACONTAHEDRON = Solid(
    vertices=tuple(_decode_vertex(vertex) for vertex in _VERTEX_CODES),
    faces=_FACES,
)


def rotate(vertex: Vec3, x_angle: float, y_angle: float, z_angle: float) -> Vec3:
    """Rotate a vertex about X, then Y, then Z without external numeric dependencies."""

    x, y, z = vertex
    cx, sx = cos(x_angle), sin(x_angle)
    y, z = y * cx - z * sx, y * sx + z * cx
    cy, sy = cos(y_angle), sin(y_angle)
    x, z = x * cy + z * sy, -x * sy + z * cy
    cz, sz = cos(z_angle), sin(z_angle)
    return x * cz - y * sz, x * sz + y * cz, z


def edge_lengths(solid: Solid) -> tuple[float, ...]:
    edges: set[tuple[int, int]] = set()
    for face in solid.faces:
        for start, end in zip(face, face[1:] + face[:1], strict=True):
            edges.add((min(start, end), max(start, end)))
    lengths = []
    for start, end in sorted(edges):
        a, b = solid.vertices[start], solid.vertices[end]
        lengths.append(sqrt(sum((a[index] - b[index]) ** 2 for index in range(3))))
    return tuple(lengths)


def manifold_edge_counts(solid: Solid) -> dict[tuple[int, int], int]:
    counts: dict[tuple[int, int], int] = {}
    for face in solid.faces:
        for start, end in zip(face, face[1:] + face[:1], strict=True):
            edge = (min(start, end), max(start, end))
            counts[edge] = counts.get(edge, 0) + 1
    return counts
