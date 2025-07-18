// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetContextKeysForCustomPolicyInput {
    /// <p>A list of policies for which you want the list of context keys referenced in those policies. Each document is specified as a string containing the complete, valid JSON text of an IAM policy.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    pub policy_input_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetContextKeysForCustomPolicyInput {
    /// <p>A list of policies for which you want the list of context keys referenced in those policies. Each document is specified as a string containing the complete, valid JSON text of an IAM policy.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.policy_input_list.is_none()`.
    pub fn policy_input_list(&self) -> &[::std::string::String] {
        self.policy_input_list.as_deref().unwrap_or_default()
    }
}
impl GetContextKeysForCustomPolicyInput {
    /// Creates a new builder-style object to manufacture [`GetContextKeysForCustomPolicyInput`](crate::operation::get_context_keys_for_custom_policy::GetContextKeysForCustomPolicyInput).
    pub fn builder() -> crate::operation::get_context_keys_for_custom_policy::builders::GetContextKeysForCustomPolicyInputBuilder {
        crate::operation::get_context_keys_for_custom_policy::builders::GetContextKeysForCustomPolicyInputBuilder::default()
    }
}

/// A builder for [`GetContextKeysForCustomPolicyInput`](crate::operation::get_context_keys_for_custom_policy::GetContextKeysForCustomPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetContextKeysForCustomPolicyInputBuilder {
    pub(crate) policy_input_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetContextKeysForCustomPolicyInputBuilder {
    /// Appends an item to `policy_input_list`.
    ///
    /// To override the contents of this collection use [`set_policy_input_list`](Self::set_policy_input_list).
    ///
    /// <p>A list of policies for which you want the list of context keys referenced in those policies. Each document is specified as a string containing the complete, valid JSON text of an IAM policy.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    pub fn policy_input_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.policy_input_list.unwrap_or_default();
        v.push(input.into());
        self.policy_input_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of policies for which you want the list of context keys referenced in those policies. Each document is specified as a string containing the complete, valid JSON text of an IAM policy.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    pub fn set_policy_input_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.policy_input_list = input;
        self
    }
    /// <p>A list of policies for which you want the list of context keys referenced in those policies. Each document is specified as a string containing the complete, valid JSON text of an IAM policy.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    pub fn get_policy_input_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.policy_input_list
    }
    /// Consumes the builder and constructs a [`GetContextKeysForCustomPolicyInput`](crate::operation::get_context_keys_for_custom_policy::GetContextKeysForCustomPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_context_keys_for_custom_policy::GetContextKeysForCustomPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_context_keys_for_custom_policy::GetContextKeysForCustomPolicyInput {
            policy_input_list: self.policy_input_list,
        })
    }
}
