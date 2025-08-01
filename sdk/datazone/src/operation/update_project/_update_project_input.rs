// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateProjectInput {
    /// <p>The ID of the Amazon DataZone domain where a project is being updated.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the project that is to be updated.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>The name to be updated as part of the <code>UpdateProject</code> action.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description to be updated as part of the <code>UpdateProject</code> action.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The glossary terms to be updated as part of the <code>UpdateProject</code> action.</p>
    pub glossary_terms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The ID of the domain unit.</p>
    pub domain_unit_id: ::std::option::Option<::std::string::String>,
    /// <p>The environment deployment details of the project.</p>
    pub environment_deployment_details: ::std::option::Option<crate::types::EnvironmentDeploymentDetails>,
    /// <p>The user parameters of the project.</p>
    pub user_parameters: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentConfigurationUserParameter>>,
    /// <p>The project profile version to which the project should be updated. You can only specify the following string for this parameter: <code>latest</code>.</p>
    pub project_profile_version: ::std::option::Option<::std::string::String>,
}
impl UpdateProjectInput {
    /// <p>The ID of the Amazon DataZone domain where a project is being updated.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The identifier of the project that is to be updated.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>The name to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The glossary terms to be updated as part of the <code>UpdateProject</code> action.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.glossary_terms.is_none()`.
    pub fn glossary_terms(&self) -> &[::std::string::String] {
        self.glossary_terms.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the domain unit.</p>
    pub fn domain_unit_id(&self) -> ::std::option::Option<&str> {
        self.domain_unit_id.as_deref()
    }
    /// <p>The environment deployment details of the project.</p>
    pub fn environment_deployment_details(&self) -> ::std::option::Option<&crate::types::EnvironmentDeploymentDetails> {
        self.environment_deployment_details.as_ref()
    }
    /// <p>The user parameters of the project.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_parameters.is_none()`.
    pub fn user_parameters(&self) -> &[crate::types::EnvironmentConfigurationUserParameter] {
        self.user_parameters.as_deref().unwrap_or_default()
    }
    /// <p>The project profile version to which the project should be updated. You can only specify the following string for this parameter: <code>latest</code>.</p>
    pub fn project_profile_version(&self) -> ::std::option::Option<&str> {
        self.project_profile_version.as_deref()
    }
}
impl ::std::fmt::Debug for UpdateProjectInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateProjectInput");
        formatter.field("domain_identifier", &self.domain_identifier);
        formatter.field("identifier", &self.identifier);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("glossary_terms", &self.glossary_terms);
        formatter.field("domain_unit_id", &self.domain_unit_id);
        formatter.field("environment_deployment_details", &self.environment_deployment_details);
        formatter.field("user_parameters", &self.user_parameters);
        formatter.field("project_profile_version", &self.project_profile_version);
        formatter.finish()
    }
}
impl UpdateProjectInput {
    /// Creates a new builder-style object to manufacture [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
    pub fn builder() -> crate::operation::update_project::builders::UpdateProjectInputBuilder {
        crate::operation::update_project::builders::UpdateProjectInputBuilder::default()
    }
}

/// A builder for [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateProjectInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) glossary_terms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) domain_unit_id: ::std::option::Option<::std::string::String>,
    pub(crate) environment_deployment_details: ::std::option::Option<crate::types::EnvironmentDeploymentDetails>,
    pub(crate) user_parameters: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentConfigurationUserParameter>>,
    pub(crate) project_profile_version: ::std::option::Option<::std::string::String>,
}
impl UpdateProjectInputBuilder {
    /// <p>The ID of the Amazon DataZone domain where a project is being updated.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain where a project is being updated.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain where a project is being updated.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The identifier of the project that is to be updated.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the project that is to be updated.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the project that is to be updated.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>The name to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `glossary_terms`.
    ///
    /// To override the contents of this collection use [`set_glossary_terms`](Self::set_glossary_terms).
    ///
    /// <p>The glossary terms to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn glossary_terms(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.glossary_terms.unwrap_or_default();
        v.push(input.into());
        self.glossary_terms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The glossary terms to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn set_glossary_terms(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.glossary_terms = input;
        self
    }
    /// <p>The glossary terms to be updated as part of the <code>UpdateProject</code> action.</p>
    pub fn get_glossary_terms(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.glossary_terms
    }
    /// <p>The ID of the domain unit.</p>
    pub fn domain_unit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_unit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the domain unit.</p>
    pub fn set_domain_unit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_unit_id = input;
        self
    }
    /// <p>The ID of the domain unit.</p>
    pub fn get_domain_unit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_unit_id
    }
    /// <p>The environment deployment details of the project.</p>
    pub fn environment_deployment_details(mut self, input: crate::types::EnvironmentDeploymentDetails) -> Self {
        self.environment_deployment_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The environment deployment details of the project.</p>
    pub fn set_environment_deployment_details(mut self, input: ::std::option::Option<crate::types::EnvironmentDeploymentDetails>) -> Self {
        self.environment_deployment_details = input;
        self
    }
    /// <p>The environment deployment details of the project.</p>
    pub fn get_environment_deployment_details(&self) -> &::std::option::Option<crate::types::EnvironmentDeploymentDetails> {
        &self.environment_deployment_details
    }
    /// Appends an item to `user_parameters`.
    ///
    /// To override the contents of this collection use [`set_user_parameters`](Self::set_user_parameters).
    ///
    /// <p>The user parameters of the project.</p>
    pub fn user_parameters(mut self, input: crate::types::EnvironmentConfigurationUserParameter) -> Self {
        let mut v = self.user_parameters.unwrap_or_default();
        v.push(input);
        self.user_parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The user parameters of the project.</p>
    pub fn set_user_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentConfigurationUserParameter>>) -> Self {
        self.user_parameters = input;
        self
    }
    /// <p>The user parameters of the project.</p>
    pub fn get_user_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EnvironmentConfigurationUserParameter>> {
        &self.user_parameters
    }
    /// <p>The project profile version to which the project should be updated. You can only specify the following string for this parameter: <code>latest</code>.</p>
    pub fn project_profile_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_profile_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The project profile version to which the project should be updated. You can only specify the following string for this parameter: <code>latest</code>.</p>
    pub fn set_project_profile_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_profile_version = input;
        self
    }
    /// <p>The project profile version to which the project should be updated. You can only specify the following string for this parameter: <code>latest</code>.</p>
    pub fn get_project_profile_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_profile_version
    }
    /// Consumes the builder and constructs a [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_project::UpdateProjectInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_project::UpdateProjectInput {
            domain_identifier: self.domain_identifier,
            identifier: self.identifier,
            name: self.name,
            description: self.description,
            glossary_terms: self.glossary_terms,
            domain_unit_id: self.domain_unit_id,
            environment_deployment_details: self.environment_deployment_details,
            user_parameters: self.user_parameters,
            project_profile_version: self.project_profile_version,
        })
    }
}
impl ::std::fmt::Debug for UpdateProjectInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateProjectInputBuilder");
        formatter.field("domain_identifier", &self.domain_identifier);
        formatter.field("identifier", &self.identifier);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("glossary_terms", &self.glossary_terms);
        formatter.field("domain_unit_id", &self.domain_unit_id);
        formatter.field("environment_deployment_details", &self.environment_deployment_details);
        formatter.field("user_parameters", &self.user_parameters);
        formatter.field("project_profile_version", &self.project_profile_version);
        formatter.finish()
    }
}
