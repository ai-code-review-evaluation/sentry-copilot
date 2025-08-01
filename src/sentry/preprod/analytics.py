from sentry import analytics


@analytics.eventclass("preprod_artifact.api.assemble")
class PreprodArtifactApiAssembleEvent(analytics.Event):
    organization_id: int
    project_id: int
    user_id: int | None = None


@analytics.eventclass("preprod_artifact.api.update")
class PreprodArtifactApiUpdateEvent(analytics.Event):
    organization_id: int
    project_id: int


@analytics.eventclass("preprod_artifact.api.assemble_generic")
class PreprodArtifactApiAssembleGenericEvent(analytics.Event):
    organization_id: int
    project_id: int


@analytics.eventclass("preprod_artifact.api.size_analysis_download")
class PreprodArtifactApiSizeAnalysisDownloadEvent(analytics.Event):
    organization_id: int
    project_id: int
    user_id: int | None = None
    artifact_id: str


@analytics.eventclass("preprod_artifact.api.get_build_details")
class PreprodArtifactApiGetBuildDetailsEvent(analytics.Event):
    organization_id: int
    project_id: int
    user_id: int | None = None
    artifact_id: str


analytics.register(PreprodArtifactApiAssembleEvent)
analytics.register(PreprodArtifactApiUpdateEvent)
analytics.register(PreprodArtifactApiAssembleGenericEvent)
analytics.register(PreprodArtifactApiSizeAnalysisDownloadEvent)
analytics.register(PreprodArtifactApiGetBuildDetailsEvent)
