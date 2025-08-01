// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DeleteTargetInput {
    /// <p>The Amazon Resource Name (ARN) of the Chatbot topic or Chatbot client to delete.</p>
    pub target_address: ::std::option::Option<::std::string::String>,
    /// <p>A Boolean value that can be used to delete all associations with this Chatbot topic. The default value is FALSE. If set to TRUE, all associations between that target and every notification rule in your Amazon Web Services account are deleted.</p>
    pub force_unsubscribe_all: ::std::option::Option<bool>,
}
impl DeleteTargetInput {
    /// <p>The Amazon Resource Name (ARN) of the Chatbot topic or Chatbot client to delete.</p>
    pub fn target_address(&self) -> ::std::option::Option<&str> {
        self.target_address.as_deref()
    }
    /// <p>A Boolean value that can be used to delete all associations with this Chatbot topic. The default value is FALSE. If set to TRUE, all associations between that target and every notification rule in your Amazon Web Services account are deleted.</p>
    pub fn force_unsubscribe_all(&self) -> ::std::option::Option<bool> {
        self.force_unsubscribe_all
    }
}
impl ::std::fmt::Debug for DeleteTargetInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeleteTargetInput");
        formatter.field("target_address", &"*** Sensitive Data Redacted ***");
        formatter.field("force_unsubscribe_all", &self.force_unsubscribe_all);
        formatter.finish()
    }
}
impl DeleteTargetInput {
    /// Creates a new builder-style object to manufacture [`DeleteTargetInput`](crate::operation::delete_target::DeleteTargetInput).
    pub fn builder() -> crate::operation::delete_target::builders::DeleteTargetInputBuilder {
        crate::operation::delete_target::builders::DeleteTargetInputBuilder::default()
    }
}

/// A builder for [`DeleteTargetInput`](crate::operation::delete_target::DeleteTargetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DeleteTargetInputBuilder {
    pub(crate) target_address: ::std::option::Option<::std::string::String>,
    pub(crate) force_unsubscribe_all: ::std::option::Option<bool>,
}
impl DeleteTargetInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Chatbot topic or Chatbot client to delete.</p>
    /// This field is required.
    pub fn target_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Chatbot topic or Chatbot client to delete.</p>
    pub fn set_target_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_address = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Chatbot topic or Chatbot client to delete.</p>
    pub fn get_target_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_address
    }
    /// <p>A Boolean value that can be used to delete all associations with this Chatbot topic. The default value is FALSE. If set to TRUE, all associations between that target and every notification rule in your Amazon Web Services account are deleted.</p>
    pub fn force_unsubscribe_all(mut self, input: bool) -> Self {
        self.force_unsubscribe_all = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value that can be used to delete all associations with this Chatbot topic. The default value is FALSE. If set to TRUE, all associations between that target and every notification rule in your Amazon Web Services account are deleted.</p>
    pub fn set_force_unsubscribe_all(mut self, input: ::std::option::Option<bool>) -> Self {
        self.force_unsubscribe_all = input;
        self
    }
    /// <p>A Boolean value that can be used to delete all associations with this Chatbot topic. The default value is FALSE. If set to TRUE, all associations between that target and every notification rule in your Amazon Web Services account are deleted.</p>
    pub fn get_force_unsubscribe_all(&self) -> &::std::option::Option<bool> {
        &self.force_unsubscribe_all
    }
    /// Consumes the builder and constructs a [`DeleteTargetInput`](crate::operation::delete_target::DeleteTargetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_target::DeleteTargetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_target::DeleteTargetInput {
            target_address: self.target_address,
            force_unsubscribe_all: self.force_unsubscribe_all,
        })
    }
}
impl ::std::fmt::Debug for DeleteTargetInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeleteTargetInputBuilder");
        formatter.field("target_address", &"*** Sensitive Data Redacted ***");
        formatter.field("force_unsubscribe_all", &self.force_unsubscribe_all);
        formatter.finish()
    }
}
