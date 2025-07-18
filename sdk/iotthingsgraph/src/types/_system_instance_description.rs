// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains a system instance definition and summary information.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SystemInstanceDescription {
    /// <p>An object that contains summary information about a system instance.</p>
    pub summary: ::std::option::Option<crate::types::SystemInstanceSummary>,
    /// <p>A document that defines an entity.</p>
    pub definition: ::std::option::Option<crate::types::DefinitionDocument>,
    /// <p>The Amazon Simple Storage Service bucket where information about a system instance is stored.</p>
    pub s3_bucket_name: ::std::option::Option<::std::string::String>,
    /// <p>An object that specifies whether cloud metrics are collected in a deployment and, if so, what role is used to collect metrics.</p>
    pub metrics_configuration: ::std::option::Option<crate::types::MetricsConfiguration>,
    /// <p>The version of the user's namespace against which the system instance was validated.</p>
    pub validated_namespace_version: ::std::option::Option<i64>,
    /// <p>A list of objects that contain all of the IDs and revision numbers of workflows and systems that are used in a system instance.</p>
    pub validated_dependency_revisions: ::std::option::Option<::std::vec::Vec<crate::types::DependencyRevision>>,
    /// <p>The AWS Identity and Access Management (IAM) role that AWS IoT Things Graph assumes during flow execution in a cloud deployment. This role must have read and write permissionss to AWS Lambda and AWS IoT and to any other AWS services that the flow uses.</p>
    pub flow_actions_role_arn: ::std::option::Option<::std::string::String>,
}
impl SystemInstanceDescription {
    /// <p>An object that contains summary information about a system instance.</p>
    pub fn summary(&self) -> ::std::option::Option<&crate::types::SystemInstanceSummary> {
        self.summary.as_ref()
    }
    /// <p>A document that defines an entity.</p>
    pub fn definition(&self) -> ::std::option::Option<&crate::types::DefinitionDocument> {
        self.definition.as_ref()
    }
    /// <p>The Amazon Simple Storage Service bucket where information about a system instance is stored.</p>
    pub fn s3_bucket_name(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_name.as_deref()
    }
    /// <p>An object that specifies whether cloud metrics are collected in a deployment and, if so, what role is used to collect metrics.</p>
    pub fn metrics_configuration(&self) -> ::std::option::Option<&crate::types::MetricsConfiguration> {
        self.metrics_configuration.as_ref()
    }
    /// <p>The version of the user's namespace against which the system instance was validated.</p>
    pub fn validated_namespace_version(&self) -> ::std::option::Option<i64> {
        self.validated_namespace_version
    }
    /// <p>A list of objects that contain all of the IDs and revision numbers of workflows and systems that are used in a system instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.validated_dependency_revisions.is_none()`.
    pub fn validated_dependency_revisions(&self) -> &[crate::types::DependencyRevision] {
        self.validated_dependency_revisions.as_deref().unwrap_or_default()
    }
    /// <p>The AWS Identity and Access Management (IAM) role that AWS IoT Things Graph assumes during flow execution in a cloud deployment. This role must have read and write permissionss to AWS Lambda and AWS IoT and to any other AWS services that the flow uses.</p>
    pub fn flow_actions_role_arn(&self) -> ::std::option::Option<&str> {
        self.flow_actions_role_arn.as_deref()
    }
}
impl SystemInstanceDescription {
    /// Creates a new builder-style object to manufacture [`SystemInstanceDescription`](crate::types::SystemInstanceDescription).
    pub fn builder() -> crate::types::builders::SystemInstanceDescriptionBuilder {
        crate::types::builders::SystemInstanceDescriptionBuilder::default()
    }
}

/// A builder for [`SystemInstanceDescription`](crate::types::SystemInstanceDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SystemInstanceDescriptionBuilder {
    pub(crate) summary: ::std::option::Option<crate::types::SystemInstanceSummary>,
    pub(crate) definition: ::std::option::Option<crate::types::DefinitionDocument>,
    pub(crate) s3_bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) metrics_configuration: ::std::option::Option<crate::types::MetricsConfiguration>,
    pub(crate) validated_namespace_version: ::std::option::Option<i64>,
    pub(crate) validated_dependency_revisions: ::std::option::Option<::std::vec::Vec<crate::types::DependencyRevision>>,
    pub(crate) flow_actions_role_arn: ::std::option::Option<::std::string::String>,
}
impl SystemInstanceDescriptionBuilder {
    /// <p>An object that contains summary information about a system instance.</p>
    pub fn summary(mut self, input: crate::types::SystemInstanceSummary) -> Self {
        self.summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains summary information about a system instance.</p>
    pub fn set_summary(mut self, input: ::std::option::Option<crate::types::SystemInstanceSummary>) -> Self {
        self.summary = input;
        self
    }
    /// <p>An object that contains summary information about a system instance.</p>
    pub fn get_summary(&self) -> &::std::option::Option<crate::types::SystemInstanceSummary> {
        &self.summary
    }
    /// <p>A document that defines an entity.</p>
    pub fn definition(mut self, input: crate::types::DefinitionDocument) -> Self {
        self.definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A document that defines an entity.</p>
    pub fn set_definition(mut self, input: ::std::option::Option<crate::types::DefinitionDocument>) -> Self {
        self.definition = input;
        self
    }
    /// <p>A document that defines an entity.</p>
    pub fn get_definition(&self) -> &::std::option::Option<crate::types::DefinitionDocument> {
        &self.definition
    }
    /// <p>The Amazon Simple Storage Service bucket where information about a system instance is stored.</p>
    pub fn s3_bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Simple Storage Service bucket where information about a system instance is stored.</p>
    pub fn set_s3_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_name = input;
        self
    }
    /// <p>The Amazon Simple Storage Service bucket where information about a system instance is stored.</p>
    pub fn get_s3_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_name
    }
    /// <p>An object that specifies whether cloud metrics are collected in a deployment and, if so, what role is used to collect metrics.</p>
    pub fn metrics_configuration(mut self, input: crate::types::MetricsConfiguration) -> Self {
        self.metrics_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that specifies whether cloud metrics are collected in a deployment and, if so, what role is used to collect metrics.</p>
    pub fn set_metrics_configuration(mut self, input: ::std::option::Option<crate::types::MetricsConfiguration>) -> Self {
        self.metrics_configuration = input;
        self
    }
    /// <p>An object that specifies whether cloud metrics are collected in a deployment and, if so, what role is used to collect metrics.</p>
    pub fn get_metrics_configuration(&self) -> &::std::option::Option<crate::types::MetricsConfiguration> {
        &self.metrics_configuration
    }
    /// <p>The version of the user's namespace against which the system instance was validated.</p>
    pub fn validated_namespace_version(mut self, input: i64) -> Self {
        self.validated_namespace_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the user's namespace against which the system instance was validated.</p>
    pub fn set_validated_namespace_version(mut self, input: ::std::option::Option<i64>) -> Self {
        self.validated_namespace_version = input;
        self
    }
    /// <p>The version of the user's namespace against which the system instance was validated.</p>
    pub fn get_validated_namespace_version(&self) -> &::std::option::Option<i64> {
        &self.validated_namespace_version
    }
    /// Appends an item to `validated_dependency_revisions`.
    ///
    /// To override the contents of this collection use [`set_validated_dependency_revisions`](Self::set_validated_dependency_revisions).
    ///
    /// <p>A list of objects that contain all of the IDs and revision numbers of workflows and systems that are used in a system instance.</p>
    pub fn validated_dependency_revisions(mut self, input: crate::types::DependencyRevision) -> Self {
        let mut v = self.validated_dependency_revisions.unwrap_or_default();
        v.push(input);
        self.validated_dependency_revisions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of objects that contain all of the IDs and revision numbers of workflows and systems that are used in a system instance.</p>
    pub fn set_validated_dependency_revisions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DependencyRevision>>) -> Self {
        self.validated_dependency_revisions = input;
        self
    }
    /// <p>A list of objects that contain all of the IDs and revision numbers of workflows and systems that are used in a system instance.</p>
    pub fn get_validated_dependency_revisions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DependencyRevision>> {
        &self.validated_dependency_revisions
    }
    /// <p>The AWS Identity and Access Management (IAM) role that AWS IoT Things Graph assumes during flow execution in a cloud deployment. This role must have read and write permissionss to AWS Lambda and AWS IoT and to any other AWS services that the flow uses.</p>
    pub fn flow_actions_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_actions_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AWS Identity and Access Management (IAM) role that AWS IoT Things Graph assumes during flow execution in a cloud deployment. This role must have read and write permissionss to AWS Lambda and AWS IoT and to any other AWS services that the flow uses.</p>
    pub fn set_flow_actions_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_actions_role_arn = input;
        self
    }
    /// <p>The AWS Identity and Access Management (IAM) role that AWS IoT Things Graph assumes during flow execution in a cloud deployment. This role must have read and write permissionss to AWS Lambda and AWS IoT and to any other AWS services that the flow uses.</p>
    pub fn get_flow_actions_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_actions_role_arn
    }
    /// Consumes the builder and constructs a [`SystemInstanceDescription`](crate::types::SystemInstanceDescription).
    pub fn build(self) -> crate::types::SystemInstanceDescription {
        crate::types::SystemInstanceDescription {
            summary: self.summary,
            definition: self.definition,
            s3_bucket_name: self.s3_bucket_name,
            metrics_configuration: self.metrics_configuration,
            validated_namespace_version: self.validated_namespace_version,
            validated_dependency_revisions: self.validated_dependency_revisions,
            flow_actions_role_arn: self.flow_actions_role_arn,
        }
    }
}
