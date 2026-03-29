"""Contracts layer -- protocols, errors, and credentials.

Runtime imports from domain only (TYPE_CHECKING imports from config for annotations).
"""

from gxassessms.core.contracts.credentials import (
    CredentialProvider as CredentialProvider,
)
from gxassessms.core.contracts.credentials import (
    EnvVarProvider as EnvVarProvider,
)
from gxassessms.core.contracts.errors import (
    AdapterError as AdapterError,
)
from gxassessms.core.contracts.errors import (
    CollectionError as CollectionError,
)
from gxassessms.core.contracts.errors import (
    ConfigError as ConfigError,
)
from gxassessms.core.contracts.errors import (
    ConfigValidationError as ConfigValidationError,
)
from gxassessms.core.contracts.errors import (
    ConsolidationError as ConsolidationError,
)
from gxassessms.core.contracts.errors import (
    DedupKeyConflictError as DedupKeyConflictError,
)
from gxassessms.core.contracts.errors import (
    GxAssessError as GxAssessError,
)
from gxassessms.core.contracts.errors import (
    InvalidRawOutputError as InvalidRawOutputError,
)
from gxassessms.core.contracts.errors import (
    InvalidTransitionError as InvalidTransitionError,
)
from gxassessms.core.contracts.errors import (
    LockTimeoutError as LockTimeoutError,
)
from gxassessms.core.contracts.errors import (
    MigrationError as MigrationError,
)
from gxassessms.core.contracts.errors import (
    MissingRawOutputError as MissingRawOutputError,
)
from gxassessms.core.contracts.errors import (
    ParseError as ParseError,
)
from gxassessms.core.contracts.errors import (
    PayloadVersionError as PayloadVersionError,
)
from gxassessms.core.contracts.errors import (
    PersistenceError as PersistenceError,
)
from gxassessms.core.contracts.errors import (
    PipelineError as PipelineError,
)
from gxassessms.core.contracts.errors import (
    PrerequisiteError as PrerequisiteError,
)
from gxassessms.core.contracts.errors import (
    QAError as QAError,
)
from gxassessms.core.contracts.errors import (
    QAQualityError as QAQualityError,
)
from gxassessms.core.contracts.errors import (
    RawOutputValidationError as RawOutputValidationError,
)
from gxassessms.core.contracts.errors import (
    RendererDependencyError as RendererDependencyError,
)
from gxassessms.core.contracts.errors import (
    ReportError as ReportError,
)
from gxassessms.core.contracts.errors import (
    StaleStageError as StaleStageError,
)
from gxassessms.core.contracts.errors import (
    TokenBudgetExhaustedError as TokenBudgetExhaustedError,
)
from gxassessms.core.contracts.types import (
    AdapterRunStatus as AdapterRunStatus,
)
from gxassessms.core.contracts.types import (
    ConsolidationRule as ConsolidationRule,
)
from gxassessms.core.contracts.types import (
    Narratives as Narratives,
)
from gxassessms.core.contracts.types import (
    PrerequisiteResult as PrerequisiteResult,
)
from gxassessms.core.contracts.types import (
    QAResult as QAResult,
)
from gxassessms.core.contracts.types import (
    QAStrategy as QAStrategy,
)
from gxassessms.core.contracts.types import (
    ReportRenderer as ReportRenderer,
)
from gxassessms.core.contracts.types import (
    ToolAdapter as ToolAdapter,
)
