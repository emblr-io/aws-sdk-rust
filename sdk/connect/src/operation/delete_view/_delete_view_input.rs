// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteViewInput {
    /// <p>The identifier of the Amazon Connect instance. You can find the instanceId in the ARN of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the view. Both <code>ViewArn</code> and <code>ViewId</code> can be used.</p>
    pub view_id: ::std::option::Option<::std::string::String>,
}
impl DeleteViewInput {
    /// <p>The identifier of the Amazon Connect instance. You can find the instanceId in the ARN of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier of the view. Both <code>ViewArn</code> and <code>ViewId</code> can be used.</p>
    pub fn view_id(&self) -> ::std::option::Option<&str> {
        self.view_id.as_deref()
    }
}
impl DeleteViewInput {
    /// Creates a new builder-style object to manufacture [`DeleteViewInput`](crate::operation::delete_view::DeleteViewInput).
    pub fn builder() -> crate::operation::delete_view::builders::DeleteViewInputBuilder {
        crate::operation::delete_view::builders::DeleteViewInputBuilder::default()
    }
}

/// A builder for [`DeleteViewInput`](crate::operation::delete_view::DeleteViewInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteViewInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) view_id: ::std::option::Option<::std::string::String>,
}
impl DeleteViewInputBuilder {
    /// <p>The identifier of the Amazon Connect instance. You can find the instanceId in the ARN of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can find the instanceId in the ARN of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can find the instanceId in the ARN of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The identifier of the view. Both <code>ViewArn</code> and <code>ViewId</code> can be used.</p>
    /// This field is required.
    pub fn view_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.view_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the view. Both <code>ViewArn</code> and <code>ViewId</code> can be used.</p>
    pub fn set_view_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.view_id = input;
        self
    }
    /// <p>The identifier of the view. Both <code>ViewArn</code> and <code>ViewId</code> can be used.</p>
    pub fn get_view_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.view_id
    }
    /// Consumes the builder and constructs a [`DeleteViewInput`](crate::operation::delete_view::DeleteViewInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_view::DeleteViewInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_view::DeleteViewInput {
            instance_id: self.instance_id,
            view_id: self.view_id,
        })
    }
}
