import fr.acinq.lightning.utils.Connection

operator fun Connection.plus(other: Connection) : Connection =
    when {
        this == other -> this
        this == Connection.ESTABLISHING || other == Connection.ESTABLISHING -> Connection.ESTABLISHING
        this is Connection.CLOSED || other is Connection.CLOSED -> Connection.CLOSED(null)
        else -> error("Cannot add [$this + $other]")
    }