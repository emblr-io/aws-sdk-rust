// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The level of detail included in each aspect of your DataSync <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-reports.html">task report</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReportOverrides {
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to transfer.</p>
    pub transferred: ::std::option::Option<crate::types::ReportOverride>,
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to verify at the end of your transfer.</p>
    pub verified: ::std::option::Option<crate::types::ReportOverride>,
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to delete in your destination location. This only applies if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub deleted: ::std::option::Option<crate::types::ReportOverride>,
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to skip during your transfer.</p>
    pub skipped: ::std::option::Option<crate::types::ReportOverride>,
}
impl ReportOverrides {
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to transfer.</p>
    pub fn transferred(&self) -> ::std::option::Option<&crate::types::ReportOverride> {
        self.transferred.as_ref()
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to verify at the end of your transfer.</p>
    pub fn verified(&self) -> ::std::option::Option<&crate::types::ReportOverride> {
        self.verified.as_ref()
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to delete in your destination location. This only applies if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub fn deleted(&self) -> ::std::option::Option<&crate::types::ReportOverride> {
        self.deleted.as_ref()
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to skip during your transfer.</p>
    pub fn skipped(&self) -> ::std::option::Option<&crate::types::ReportOverride> {
        self.skipped.as_ref()
    }
}
impl ReportOverrides {
    /// Creates a new builder-style object to manufacture [`ReportOverrides`](crate::types::ReportOverrides).
    pub fn builder() -> crate::types::builders::ReportOverridesBuilder {
        crate::types::builders::ReportOverridesBuilder::default()
    }
}

/// A builder for [`ReportOverrides`](crate::types::ReportOverrides).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReportOverridesBuilder {
    pub(crate) transferred: ::std::option::Option<crate::types::ReportOverride>,
    pub(crate) verified: ::std::option::Option<crate::types::ReportOverride>,
    pub(crate) deleted: ::std::option::Option<crate::types::ReportOverride>,
    pub(crate) skipped: ::std::option::Option<crate::types::ReportOverride>,
}
impl ReportOverridesBuilder {
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to transfer.</p>
    pub fn transferred(mut self, input: crate::types::ReportOverride) -> Self {
        self.transferred = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to transfer.</p>
    pub fn set_transferred(mut self, input: ::std::option::Option<crate::types::ReportOverride>) -> Self {
        self.transferred = input;
        self
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to transfer.</p>
    pub fn get_transferred(&self) -> &::std::option::Option<crate::types::ReportOverride> {
        &self.transferred
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to verify at the end of your transfer.</p>
    pub fn verified(mut self, input: crate::types::ReportOverride) -> Self {
        self.verified = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to verify at the end of your transfer.</p>
    pub fn set_verified(mut self, input: ::std::option::Option<crate::types::ReportOverride>) -> Self {
        self.verified = input;
        self
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to verify at the end of your transfer.</p>
    pub fn get_verified(&self) -> &::std::option::Option<crate::types::ReportOverride> {
        &self.verified
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to delete in your destination location. This only applies if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub fn deleted(mut self, input: crate::types::ReportOverride) -> Self {
        self.deleted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to delete in your destination location. This only applies if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub fn set_deleted(mut self, input: ::std::option::Option<crate::types::ReportOverride>) -> Self {
        self.deleted = input;
        self
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to delete in your destination location. This only applies if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub fn get_deleted(&self) -> &::std::option::Option<crate::types::ReportOverride> {
        &self.deleted
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to skip during your transfer.</p>
    pub fn skipped(mut self, input: crate::types::ReportOverride) -> Self {
        self.skipped = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to skip during your transfer.</p>
    pub fn set_skipped(mut self, input: ::std::option::Option<crate::types::ReportOverride>) -> Self {
        self.skipped = input;
        self
    }
    /// <p>Specifies the level of reporting for the files, objects, and directories that DataSync attempted to skip during your transfer.</p>
    pub fn get_skipped(&self) -> &::std::option::Option<crate::types::ReportOverride> {
        &self.skipped
    }
    /// Consumes the builder and constructs a [`ReportOverrides`](crate::types::ReportOverrides).
    pub fn build(self) -> crate::types::ReportOverrides {
        crate::types::ReportOverrides {
            transferred: self.transferred,
            verified: self.verified,
            deleted: self.deleted,
            skipped: self.skipped,
        }
    }
}
