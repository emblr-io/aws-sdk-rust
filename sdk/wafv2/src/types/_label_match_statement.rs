// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A rule statement to match against labels that have been added to the web request by rules that have already run in the web ACL.</p>
/// <p>The label match statement provides the label or namespace string to search for. The label string can represent a part or all of the fully qualified label name that had been added to the web request. Fully qualified labels have a prefix, optional namespaces, and label name. The prefix identifies the rule group or web ACL context of the rule that added the label. If you do not provide the fully qualified name in your label match string, WAF performs the search for labels that were added in the same context as the label match statement.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LabelMatchStatement {
    /// <p>Specify whether you want to match using the label name or just the namespace.</p>
    pub scope: crate::types::LabelMatchScope,
    /// <p>The string to match against. The setting you provide for this depends on the match statement's <code>Scope</code> setting:</p>
    /// <ul>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>LABEL</code>, then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name.</p></li>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>NAMESPACE</code>, then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates.</p></li>
    /// </ul>
    /// <p>Labels are case sensitive and components of a label must be separated by colon, for example <code>NS1:NS2:name</code>.</p>
    pub key: ::std::string::String,
}
impl LabelMatchStatement {
    /// <p>Specify whether you want to match using the label name or just the namespace.</p>
    pub fn scope(&self) -> &crate::types::LabelMatchScope {
        &self.scope
    }
    /// <p>The string to match against. The setting you provide for this depends on the match statement's <code>Scope</code> setting:</p>
    /// <ul>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>LABEL</code>, then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name.</p></li>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>NAMESPACE</code>, then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates.</p></li>
    /// </ul>
    /// <p>Labels are case sensitive and components of a label must be separated by colon, for example <code>NS1:NS2:name</code>.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
}
impl LabelMatchStatement {
    /// Creates a new builder-style object to manufacture [`LabelMatchStatement`](crate::types::LabelMatchStatement).
    pub fn builder() -> crate::types::builders::LabelMatchStatementBuilder {
        crate::types::builders::LabelMatchStatementBuilder::default()
    }
}

/// A builder for [`LabelMatchStatement`](crate::types::LabelMatchStatement).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LabelMatchStatementBuilder {
    pub(crate) scope: ::std::option::Option<crate::types::LabelMatchScope>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
}
impl LabelMatchStatementBuilder {
    /// <p>Specify whether you want to match using the label name or just the namespace.</p>
    /// This field is required.
    pub fn scope(mut self, input: crate::types::LabelMatchScope) -> Self {
        self.scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify whether you want to match using the label name or just the namespace.</p>
    pub fn set_scope(mut self, input: ::std::option::Option<crate::types::LabelMatchScope>) -> Self {
        self.scope = input;
        self
    }
    /// <p>Specify whether you want to match using the label name or just the namespace.</p>
    pub fn get_scope(&self) -> &::std::option::Option<crate::types::LabelMatchScope> {
        &self.scope
    }
    /// <p>The string to match against. The setting you provide for this depends on the match statement's <code>Scope</code> setting:</p>
    /// <ul>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>LABEL</code>, then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name.</p></li>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>NAMESPACE</code>, then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates.</p></li>
    /// </ul>
    /// <p>Labels are case sensitive and components of a label must be separated by colon, for example <code>NS1:NS2:name</code>.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string to match against. The setting you provide for this depends on the match statement's <code>Scope</code> setting:</p>
    /// <ul>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>LABEL</code>, then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name.</p></li>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>NAMESPACE</code>, then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates.</p></li>
    /// </ul>
    /// <p>Labels are case sensitive and components of a label must be separated by colon, for example <code>NS1:NS2:name</code>.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The string to match against. The setting you provide for this depends on the match statement's <code>Scope</code> setting:</p>
    /// <ul>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>LABEL</code>, then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name.</p></li>
    /// <li>
    /// <p>If the <code>Scope</code> indicates <code>NAMESPACE</code>, then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates.</p></li>
    /// </ul>
    /// <p>Labels are case sensitive and components of a label must be separated by colon, for example <code>NS1:NS2:name</code>.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// Consumes the builder and constructs a [`LabelMatchStatement`](crate::types::LabelMatchStatement).
    /// This method will fail if any of the following fields are not set:
    /// - [`scope`](crate::types::builders::LabelMatchStatementBuilder::scope)
    /// - [`key`](crate::types::builders::LabelMatchStatementBuilder::key)
    pub fn build(self) -> ::std::result::Result<crate::types::LabelMatchStatement, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LabelMatchStatement {
            scope: self.scope.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scope",
                    "scope was not specified but it is required when building LabelMatchStatement",
                )
            })?,
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building LabelMatchStatement",
                )
            })?,
        })
    }
}
