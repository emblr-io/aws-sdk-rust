// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListComponentProvisionedResourcesInput {
    /// <p>The name of the component whose provisioned resources you want.</p>
    pub component_name: ::std::option::Option<::std::string::String>,
    /// <p>A token that indicates the location of the next provisioned resource in the array of provisioned resources, after the list of provisioned resources that was previously requested.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListComponentProvisionedResourcesInput {
    /// <p>The name of the component whose provisioned resources you want.</p>
    pub fn component_name(&self) -> ::std::option::Option<&str> {
        self.component_name.as_deref()
    }
    /// <p>A token that indicates the location of the next provisioned resource in the array of provisioned resources, after the list of provisioned resources that was previously requested.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListComponentProvisionedResourcesInput {
    /// Creates a new builder-style object to manufacture [`ListComponentProvisionedResourcesInput`](crate::operation::list_component_provisioned_resources::ListComponentProvisionedResourcesInput).
    pub fn builder() -> crate::operation::list_component_provisioned_resources::builders::ListComponentProvisionedResourcesInputBuilder {
        crate::operation::list_component_provisioned_resources::builders::ListComponentProvisionedResourcesInputBuilder::default()
    }
}

/// A builder for [`ListComponentProvisionedResourcesInput`](crate::operation::list_component_provisioned_resources::ListComponentProvisionedResourcesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListComponentProvisionedResourcesInputBuilder {
    pub(crate) component_name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListComponentProvisionedResourcesInputBuilder {
    /// <p>The name of the component whose provisioned resources you want.</p>
    /// This field is required.
    pub fn component_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the component whose provisioned resources you want.</p>
    pub fn set_component_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_name = input;
        self
    }
    /// <p>The name of the component whose provisioned resources you want.</p>
    pub fn get_component_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_name
    }
    /// <p>A token that indicates the location of the next provisioned resource in the array of provisioned resources, after the list of provisioned resources that was previously requested.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates the location of the next provisioned resource in the array of provisioned resources, after the list of provisioned resources that was previously requested.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates the location of the next provisioned resource in the array of provisioned resources, after the list of provisioned resources that was previously requested.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListComponentProvisionedResourcesInput`](crate::operation::list_component_provisioned_resources::ListComponentProvisionedResourcesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_component_provisioned_resources::ListComponentProvisionedResourcesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_component_provisioned_resources::ListComponentProvisionedResourcesInput {
                component_name: self.component_name,
                next_token: self.next_token,
            },
        )
    }
}
