// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFileSystemPolicyInput {
    /// <p>Specifies which EFS file system to retrieve the <code>FileSystemPolicy</code> for.</p>
    pub file_system_id: ::std::option::Option<::std::string::String>,
}
impl DescribeFileSystemPolicyInput {
    /// <p>Specifies which EFS file system to retrieve the <code>FileSystemPolicy</code> for.</p>
    pub fn file_system_id(&self) -> ::std::option::Option<&str> {
        self.file_system_id.as_deref()
    }
}
impl DescribeFileSystemPolicyInput {
    /// Creates a new builder-style object to manufacture [`DescribeFileSystemPolicyInput`](crate::operation::describe_file_system_policy::DescribeFileSystemPolicyInput).
    pub fn builder() -> crate::operation::describe_file_system_policy::builders::DescribeFileSystemPolicyInputBuilder {
        crate::operation::describe_file_system_policy::builders::DescribeFileSystemPolicyInputBuilder::default()
    }
}

/// A builder for [`DescribeFileSystemPolicyInput`](crate::operation::describe_file_system_policy::DescribeFileSystemPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFileSystemPolicyInputBuilder {
    pub(crate) file_system_id: ::std::option::Option<::std::string::String>,
}
impl DescribeFileSystemPolicyInputBuilder {
    /// <p>Specifies which EFS file system to retrieve the <code>FileSystemPolicy</code> for.</p>
    /// This field is required.
    pub fn file_system_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies which EFS file system to retrieve the <code>FileSystemPolicy</code> for.</p>
    pub fn set_file_system_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_id = input;
        self
    }
    /// <p>Specifies which EFS file system to retrieve the <code>FileSystemPolicy</code> for.</p>
    pub fn get_file_system_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_id
    }
    /// Consumes the builder and constructs a [`DescribeFileSystemPolicyInput`](crate::operation::describe_file_system_policy::DescribeFileSystemPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_file_system_policy::DescribeFileSystemPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_file_system_policy::DescribeFileSystemPolicyInput {
            file_system_id: self.file_system_id,
        })
    }
}
