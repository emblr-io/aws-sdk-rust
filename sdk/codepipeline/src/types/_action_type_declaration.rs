// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for the action type definition that are provided when the action type is created or updated.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActionTypeDeclaration {
    /// <p>The description for the action type to be updated.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Information about the executor for an action type that was created with any supported integration model.</p>
    pub executor: ::std::option::Option<crate::types::ActionTypeExecutor>,
    /// <p>The action category, owner, provider, and version of the action type to be updated.</p>
    pub id: ::std::option::Option<crate::types::ActionTypeIdentifier>,
    /// <p>Details for the artifacts, such as application files, to be worked on by the action. For example, the minimum and maximum number of input artifacts allowed.</p>
    pub input_artifact_details: ::std::option::Option<crate::types::ActionTypeArtifactDetails>,
    /// <p>Details for the output artifacts, such as a built application, that are the result of the action. For example, the minimum and maximum number of output artifacts allowed.</p>
    pub output_artifact_details: ::std::option::Option<crate::types::ActionTypeArtifactDetails>,
    /// <p>Details identifying the accounts with permissions to use the action type.</p>
    pub permissions: ::std::option::Option<crate::types::ActionTypePermissions>,
    /// <p>The properties of the action type to be updated.</p>
    pub properties: ::std::option::Option<::std::vec::Vec<crate::types::ActionTypeProperty>>,
    /// <p>The links associated with the action type to be updated.</p>
    pub urls: ::std::option::Option<crate::types::ActionTypeUrls>,
}
impl ActionTypeDeclaration {
    /// <p>The description for the action type to be updated.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Information about the executor for an action type that was created with any supported integration model.</p>
    pub fn executor(&self) -> ::std::option::Option<&crate::types::ActionTypeExecutor> {
        self.executor.as_ref()
    }
    /// <p>The action category, owner, provider, and version of the action type to be updated.</p>
    pub fn id(&self) -> ::std::option::Option<&crate::types::ActionTypeIdentifier> {
        self.id.as_ref()
    }
    /// <p>Details for the artifacts, such as application files, to be worked on by the action. For example, the minimum and maximum number of input artifacts allowed.</p>
    pub fn input_artifact_details(&self) -> ::std::option::Option<&crate::types::ActionTypeArtifactDetails> {
        self.input_artifact_details.as_ref()
    }
    /// <p>Details for the output artifacts, such as a built application, that are the result of the action. For example, the minimum and maximum number of output artifacts allowed.</p>
    pub fn output_artifact_details(&self) -> ::std::option::Option<&crate::types::ActionTypeArtifactDetails> {
        self.output_artifact_details.as_ref()
    }
    /// <p>Details identifying the accounts with permissions to use the action type.</p>
    pub fn permissions(&self) -> ::std::option::Option<&crate::types::ActionTypePermissions> {
        self.permissions.as_ref()
    }
    /// <p>The properties of the action type to be updated.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.properties.is_none()`.
    pub fn properties(&self) -> &[crate::types::ActionTypeProperty] {
        self.properties.as_deref().unwrap_or_default()
    }
    /// <p>The links associated with the action type to be updated.</p>
    pub fn urls(&self) -> ::std::option::Option<&crate::types::ActionTypeUrls> {
        self.urls.as_ref()
    }
}
impl ActionTypeDeclaration {
    /// Creates a new builder-style object to manufacture [`ActionTypeDeclaration`](crate::types::ActionTypeDeclaration).
    pub fn builder() -> crate::types::builders::ActionTypeDeclarationBuilder {
        crate::types::builders::ActionTypeDeclarationBuilder::default()
    }
}

/// A builder for [`ActionTypeDeclaration`](crate::types::ActionTypeDeclaration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActionTypeDeclarationBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) executor: ::std::option::Option<crate::types::ActionTypeExecutor>,
    pub(crate) id: ::std::option::Option<crate::types::ActionTypeIdentifier>,
    pub(crate) input_artifact_details: ::std::option::Option<crate::types::ActionTypeArtifactDetails>,
    pub(crate) output_artifact_details: ::std::option::Option<crate::types::ActionTypeArtifactDetails>,
    pub(crate) permissions: ::std::option::Option<crate::types::ActionTypePermissions>,
    pub(crate) properties: ::std::option::Option<::std::vec::Vec<crate::types::ActionTypeProperty>>,
    pub(crate) urls: ::std::option::Option<crate::types::ActionTypeUrls>,
}
impl ActionTypeDeclarationBuilder {
    /// <p>The description for the action type to be updated.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for the action type to be updated.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description for the action type to be updated.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Information about the executor for an action type that was created with any supported integration model.</p>
    /// This field is required.
    pub fn executor(mut self, input: crate::types::ActionTypeExecutor) -> Self {
        self.executor = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the executor for an action type that was created with any supported integration model.</p>
    pub fn set_executor(mut self, input: ::std::option::Option<crate::types::ActionTypeExecutor>) -> Self {
        self.executor = input;
        self
    }
    /// <p>Information about the executor for an action type that was created with any supported integration model.</p>
    pub fn get_executor(&self) -> &::std::option::Option<crate::types::ActionTypeExecutor> {
        &self.executor
    }
    /// <p>The action category, owner, provider, and version of the action type to be updated.</p>
    /// This field is required.
    pub fn id(mut self, input: crate::types::ActionTypeIdentifier) -> Self {
        self.id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action category, owner, provider, and version of the action type to be updated.</p>
    pub fn set_id(mut self, input: ::std::option::Option<crate::types::ActionTypeIdentifier>) -> Self {
        self.id = input;
        self
    }
    /// <p>The action category, owner, provider, and version of the action type to be updated.</p>
    pub fn get_id(&self) -> &::std::option::Option<crate::types::ActionTypeIdentifier> {
        &self.id
    }
    /// <p>Details for the artifacts, such as application files, to be worked on by the action. For example, the minimum and maximum number of input artifacts allowed.</p>
    /// This field is required.
    pub fn input_artifact_details(mut self, input: crate::types::ActionTypeArtifactDetails) -> Self {
        self.input_artifact_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details for the artifacts, such as application files, to be worked on by the action. For example, the minimum and maximum number of input artifacts allowed.</p>
    pub fn set_input_artifact_details(mut self, input: ::std::option::Option<crate::types::ActionTypeArtifactDetails>) -> Self {
        self.input_artifact_details = input;
        self
    }
    /// <p>Details for the artifacts, such as application files, to be worked on by the action. For example, the minimum and maximum number of input artifacts allowed.</p>
    pub fn get_input_artifact_details(&self) -> &::std::option::Option<crate::types::ActionTypeArtifactDetails> {
        &self.input_artifact_details
    }
    /// <p>Details for the output artifacts, such as a built application, that are the result of the action. For example, the minimum and maximum number of output artifacts allowed.</p>
    /// This field is required.
    pub fn output_artifact_details(mut self, input: crate::types::ActionTypeArtifactDetails) -> Self {
        self.output_artifact_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details for the output artifacts, such as a built application, that are the result of the action. For example, the minimum and maximum number of output artifacts allowed.</p>
    pub fn set_output_artifact_details(mut self, input: ::std::option::Option<crate::types::ActionTypeArtifactDetails>) -> Self {
        self.output_artifact_details = input;
        self
    }
    /// <p>Details for the output artifacts, such as a built application, that are the result of the action. For example, the minimum and maximum number of output artifacts allowed.</p>
    pub fn get_output_artifact_details(&self) -> &::std::option::Option<crate::types::ActionTypeArtifactDetails> {
        &self.output_artifact_details
    }
    /// <p>Details identifying the accounts with permissions to use the action type.</p>
    pub fn permissions(mut self, input: crate::types::ActionTypePermissions) -> Self {
        self.permissions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details identifying the accounts with permissions to use the action type.</p>
    pub fn set_permissions(mut self, input: ::std::option::Option<crate::types::ActionTypePermissions>) -> Self {
        self.permissions = input;
        self
    }
    /// <p>Details identifying the accounts with permissions to use the action type.</p>
    pub fn get_permissions(&self) -> &::std::option::Option<crate::types::ActionTypePermissions> {
        &self.permissions
    }
    /// Appends an item to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>The properties of the action type to be updated.</p>
    pub fn properties(mut self, input: crate::types::ActionTypeProperty) -> Self {
        let mut v = self.properties.unwrap_or_default();
        v.push(input);
        self.properties = ::std::option::Option::Some(v);
        self
    }
    /// <p>The properties of the action type to be updated.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ActionTypeProperty>>) -> Self {
        self.properties = input;
        self
    }
    /// <p>The properties of the action type to be updated.</p>
    pub fn get_properties(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ActionTypeProperty>> {
        &self.properties
    }
    /// <p>The links associated with the action type to be updated.</p>
    pub fn urls(mut self, input: crate::types::ActionTypeUrls) -> Self {
        self.urls = ::std::option::Option::Some(input);
        self
    }
    /// <p>The links associated with the action type to be updated.</p>
    pub fn set_urls(mut self, input: ::std::option::Option<crate::types::ActionTypeUrls>) -> Self {
        self.urls = input;
        self
    }
    /// <p>The links associated with the action type to be updated.</p>
    pub fn get_urls(&self) -> &::std::option::Option<crate::types::ActionTypeUrls> {
        &self.urls
    }
    /// Consumes the builder and constructs a [`ActionTypeDeclaration`](crate::types::ActionTypeDeclaration).
    pub fn build(self) -> crate::types::ActionTypeDeclaration {
        crate::types::ActionTypeDeclaration {
            description: self.description,
            executor: self.executor,
            id: self.id,
            input_artifact_details: self.input_artifact_details,
            output_artifact_details: self.output_artifact_details,
            permissions: self.permissions,
            properties: self.properties,
            urls: self.urls,
        }
    }
}
