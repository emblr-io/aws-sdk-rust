// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateServiceInput {
    /// <p>The name of the service to edit.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The edited service description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Lists the service instances to add and the existing service instances to remain. Omit the existing service instances to delete from the list. <i>Don't</i> include edits to the existing service instances or pipeline. For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/ag-svc-update.html">Edit a service</a> in the <i>Proton User Guide</i>.</p>
    pub spec: ::std::option::Option<::std::string::String>,
}
impl UpdateServiceInput {
    /// <p>The name of the service to edit.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The edited service description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Lists the service instances to add and the existing service instances to remain. Omit the existing service instances to delete from the list. <i>Don't</i> include edits to the existing service instances or pipeline. For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/ag-svc-update.html">Edit a service</a> in the <i>Proton User Guide</i>.</p>
    pub fn spec(&self) -> ::std::option::Option<&str> {
        self.spec.as_deref()
    }
}
impl ::std::fmt::Debug for UpdateServiceInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateServiceInput");
        formatter.field("name", &self.name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("spec", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl UpdateServiceInput {
    /// Creates a new builder-style object to manufacture [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
    pub fn builder() -> crate::operation::update_service::builders::UpdateServiceInputBuilder {
        crate::operation::update_service::builders::UpdateServiceInputBuilder::default()
    }
}

/// A builder for [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateServiceInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) spec: ::std::option::Option<::std::string::String>,
}
impl UpdateServiceInputBuilder {
    /// <p>The name of the service to edit.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service to edit.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the service to edit.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The edited service description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The edited service description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The edited service description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Lists the service instances to add and the existing service instances to remain. Omit the existing service instances to delete from the list. <i>Don't</i> include edits to the existing service instances or pipeline. For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/ag-svc-update.html">Edit a service</a> in the <i>Proton User Guide</i>.</p>
    pub fn spec(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.spec = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Lists the service instances to add and the existing service instances to remain. Omit the existing service instances to delete from the list. <i>Don't</i> include edits to the existing service instances or pipeline. For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/ag-svc-update.html">Edit a service</a> in the <i>Proton User Guide</i>.</p>
    pub fn set_spec(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.spec = input;
        self
    }
    /// <p>Lists the service instances to add and the existing service instances to remain. Omit the existing service instances to delete from the list. <i>Don't</i> include edits to the existing service instances or pipeline. For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/ag-svc-update.html">Edit a service</a> in the <i>Proton User Guide</i>.</p>
    pub fn get_spec(&self) -> &::std::option::Option<::std::string::String> {
        &self.spec
    }
    /// Consumes the builder and constructs a [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_service::UpdateServiceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_service::UpdateServiceInput {
            name: self.name,
            description: self.description,
            spec: self.spec,
        })
    }
}
impl ::std::fmt::Debug for UpdateServiceInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateServiceInputBuilder");
        formatter.field("name", &self.name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("spec", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
