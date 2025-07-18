// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>DetachObject</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchDetachObject {
    /// <p>Parent reference from which the object with the specified link name is detached.</p>
    pub parent_reference: ::std::option::Option<crate::types::ObjectReference>,
    /// <p>The name of the link.</p>
    pub link_name: ::std::string::String,
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub batch_reference_name: ::std::option::Option<::std::string::String>,
}
impl BatchDetachObject {
    /// <p>Parent reference from which the object with the specified link name is detached.</p>
    pub fn parent_reference(&self) -> ::std::option::Option<&crate::types::ObjectReference> {
        self.parent_reference.as_ref()
    }
    /// <p>The name of the link.</p>
    pub fn link_name(&self) -> &str {
        use std::ops::Deref;
        self.link_name.deref()
    }
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub fn batch_reference_name(&self) -> ::std::option::Option<&str> {
        self.batch_reference_name.as_deref()
    }
}
impl BatchDetachObject {
    /// Creates a new builder-style object to manufacture [`BatchDetachObject`](crate::types::BatchDetachObject).
    pub fn builder() -> crate::types::builders::BatchDetachObjectBuilder {
        crate::types::builders::BatchDetachObjectBuilder::default()
    }
}

/// A builder for [`BatchDetachObject`](crate::types::BatchDetachObject).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchDetachObjectBuilder {
    pub(crate) parent_reference: ::std::option::Option<crate::types::ObjectReference>,
    pub(crate) link_name: ::std::option::Option<::std::string::String>,
    pub(crate) batch_reference_name: ::std::option::Option<::std::string::String>,
}
impl BatchDetachObjectBuilder {
    /// <p>Parent reference from which the object with the specified link name is detached.</p>
    /// This field is required.
    pub fn parent_reference(mut self, input: crate::types::ObjectReference) -> Self {
        self.parent_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>Parent reference from which the object with the specified link name is detached.</p>
    pub fn set_parent_reference(mut self, input: ::std::option::Option<crate::types::ObjectReference>) -> Self {
        self.parent_reference = input;
        self
    }
    /// <p>Parent reference from which the object with the specified link name is detached.</p>
    pub fn get_parent_reference(&self) -> &::std::option::Option<crate::types::ObjectReference> {
        &self.parent_reference
    }
    /// <p>The name of the link.</p>
    /// This field is required.
    pub fn link_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.link_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the link.</p>
    pub fn set_link_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.link_name = input;
        self
    }
    /// <p>The name of the link.</p>
    pub fn get_link_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.link_name
    }
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub fn batch_reference_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.batch_reference_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub fn set_batch_reference_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.batch_reference_name = input;
        self
    }
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub fn get_batch_reference_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.batch_reference_name
    }
    /// Consumes the builder and constructs a [`BatchDetachObject`](crate::types::BatchDetachObject).
    /// This method will fail if any of the following fields are not set:
    /// - [`link_name`](crate::types::builders::BatchDetachObjectBuilder::link_name)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchDetachObject, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchDetachObject {
            parent_reference: self.parent_reference,
            link_name: self.link_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "link_name",
                    "link_name was not specified but it is required when building BatchDetachObject",
                )
            })?,
            batch_reference_name: self.batch_reference_name,
        })
    }
}
