// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UngroupResourcesInput {
    /// <p>The name or the Amazon resource name (ARN) of the resource group from which to remove the resources.</p>
    pub group: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon resource names (ARNs) of the resources to be removed from the group.</p>
    pub resource_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UngroupResourcesInput {
    /// <p>The name or the Amazon resource name (ARN) of the resource group from which to remove the resources.</p>
    pub fn group(&self) -> ::std::option::Option<&str> {
        self.group.as_deref()
    }
    /// <p>The Amazon resource names (ARNs) of the resources to be removed from the group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_arns.is_none()`.
    pub fn resource_arns(&self) -> &[::std::string::String] {
        self.resource_arns.as_deref().unwrap_or_default()
    }
}
impl UngroupResourcesInput {
    /// Creates a new builder-style object to manufacture [`UngroupResourcesInput`](crate::operation::ungroup_resources::UngroupResourcesInput).
    pub fn builder() -> crate::operation::ungroup_resources::builders::UngroupResourcesInputBuilder {
        crate::operation::ungroup_resources::builders::UngroupResourcesInputBuilder::default()
    }
}

/// A builder for [`UngroupResourcesInput`](crate::operation::ungroup_resources::UngroupResourcesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UngroupResourcesInputBuilder {
    pub(crate) group: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UngroupResourcesInputBuilder {
    /// <p>The name or the Amazon resource name (ARN) of the resource group from which to remove the resources.</p>
    /// This field is required.
    pub fn group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or the Amazon resource name (ARN) of the resource group from which to remove the resources.</p>
    pub fn set_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group = input;
        self
    }
    /// <p>The name or the Amazon resource name (ARN) of the resource group from which to remove the resources.</p>
    pub fn get_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.group
    }
    /// Appends an item to `resource_arns`.
    ///
    /// To override the contents of this collection use [`set_resource_arns`](Self::set_resource_arns).
    ///
    /// <p>The Amazon resource names (ARNs) of the resources to be removed from the group.</p>
    pub fn resource_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_arns.unwrap_or_default();
        v.push(input.into());
        self.resource_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon resource names (ARNs) of the resources to be removed from the group.</p>
    pub fn set_resource_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_arns = input;
        self
    }
    /// <p>The Amazon resource names (ARNs) of the resources to be removed from the group.</p>
    pub fn get_resource_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_arns
    }
    /// Consumes the builder and constructs a [`UngroupResourcesInput`](crate::operation::ungroup_resources::UngroupResourcesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::ungroup_resources::UngroupResourcesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::ungroup_resources::UngroupResourcesInput {
            group: self.group,
            resource_arns: self.resource_arns,
        })
    }
}
