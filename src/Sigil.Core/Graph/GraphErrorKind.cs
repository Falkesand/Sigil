namespace Sigil.Graph;

public enum GraphErrorKind
{
    NodeNotFound,
    DuplicateNode,
    InvalidEdge,
    DeserializationFailed,
    SerializationFailed,
    ScanFailed,
    FileNotFound,
    InvalidFormat
}
