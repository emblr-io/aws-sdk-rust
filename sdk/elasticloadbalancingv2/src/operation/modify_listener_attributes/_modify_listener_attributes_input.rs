// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyListenerAttributesInput {
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub listener_arn: ::std::option::Option<::std::string::String>,
    /// <p>The listener attributes.</p>
    pub attributes: ::std::option::Option<::std::vec::Vec<crate::types::ListenerAttribute>>,
}
impl ModifyListenerAttributesInput {
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub fn listener_arn(&self) -> ::std::option::Option<&str> {
        self.listener_arn.as_deref()
    }
    /// <p>The listener attributes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes.is_none()`.
    pub fn attributes(&self) -> &[crate::types::ListenerAttribute] {
        self.attributes.as_deref().unwrap_or_default()
    }
}
impl ModifyListenerAttributesInput {
    /// Creates a new builder-style object to manufacture [`ModifyListenerAttributesInput`](crate::operation::modify_listener_attributes::ModifyListenerAttributesInput).
    pub fn builder() -> crate::operation::modify_listener_attributes::builders::ModifyListenerAttributesInputBuilder {
        crate::operation::modify_listener_attributes::builders::ModifyListenerAttributesInputBuilder::default()
    }
}

/// A builder for [`ModifyListenerAttributesInput`](crate::operation::modify_listener_attributes::ModifyListenerAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyListenerAttributesInputBuilder {
    pub(crate) listener_arn: ::std::option::Option<::std::string::String>,
    pub(crate) attributes: ::std::option::Option<::std::vec::Vec<crate::types::ListenerAttribute>>,
}
impl ModifyListenerAttributesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    /// This field is required.
    pub fn listener_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.listener_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub fn set_listener_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.listener_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub fn get_listener_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.listener_arn
    }
    /// Appends an item to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>The listener attributes.</p>
    pub fn attributes(mut self, input: crate::types::ListenerAttribute) -> Self {
        let mut v = self.attributes.unwrap_or_default();
        v.push(input);
        self.attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The listener attributes.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ListenerAttribute>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>The listener attributes.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ListenerAttribute>> {
        &self.attributes
    }
    /// Consumes the builder and constructs a [`ModifyListenerAttributesInput`](crate::operation::modify_listener_attributes::ModifyListenerAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_listener_attributes::ModifyListenerAttributesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_listener_attributes::ModifyListenerAttributesInput {
            listener_arn: self.listener_arn,
            attributes: self.attributes,
        })
    }
}
