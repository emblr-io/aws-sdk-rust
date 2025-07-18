// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The system generated response showing the DNS aliases that Amazon FSx is attempting to associate with the file system. Use the API operation to monitor the status of the aliases Amazon FSx is associating with the file system. It can take up to 2.5 minutes for the alias status to change from <code>CREATING</code> to <code>AVAILABLE</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateFileSystemAliasesOutput {
    /// <p>An array of the DNS aliases that Amazon FSx is associating with the file system.</p>
    pub aliases: ::std::option::Option<::std::vec::Vec<crate::types::Alias>>,
    _request_id: Option<String>,
}
impl AssociateFileSystemAliasesOutput {
    /// <p>An array of the DNS aliases that Amazon FSx is associating with the file system.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.aliases.is_none()`.
    pub fn aliases(&self) -> &[crate::types::Alias] {
        self.aliases.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for AssociateFileSystemAliasesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateFileSystemAliasesOutput {
    /// Creates a new builder-style object to manufacture [`AssociateFileSystemAliasesOutput`](crate::operation::associate_file_system_aliases::AssociateFileSystemAliasesOutput).
    pub fn builder() -> crate::operation::associate_file_system_aliases::builders::AssociateFileSystemAliasesOutputBuilder {
        crate::operation::associate_file_system_aliases::builders::AssociateFileSystemAliasesOutputBuilder::default()
    }
}

/// A builder for [`AssociateFileSystemAliasesOutput`](crate::operation::associate_file_system_aliases::AssociateFileSystemAliasesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateFileSystemAliasesOutputBuilder {
    pub(crate) aliases: ::std::option::Option<::std::vec::Vec<crate::types::Alias>>,
    _request_id: Option<String>,
}
impl AssociateFileSystemAliasesOutputBuilder {
    /// Appends an item to `aliases`.
    ///
    /// To override the contents of this collection use [`set_aliases`](Self::set_aliases).
    ///
    /// <p>An array of the DNS aliases that Amazon FSx is associating with the file system.</p>
    pub fn aliases(mut self, input: crate::types::Alias) -> Self {
        let mut v = self.aliases.unwrap_or_default();
        v.push(input);
        self.aliases = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of the DNS aliases that Amazon FSx is associating with the file system.</p>
    pub fn set_aliases(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Alias>>) -> Self {
        self.aliases = input;
        self
    }
    /// <p>An array of the DNS aliases that Amazon FSx is associating with the file system.</p>
    pub fn get_aliases(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Alias>> {
        &self.aliases
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateFileSystemAliasesOutput`](crate::operation::associate_file_system_aliases::AssociateFileSystemAliasesOutput).
    pub fn build(self) -> crate::operation::associate_file_system_aliases::AssociateFileSystemAliasesOutput {
        crate::operation::associate_file_system_aliases::AssociateFileSystemAliasesOutput {
            aliases: self.aliases,
            _request_id: self._request_id,
        }
    }
}
