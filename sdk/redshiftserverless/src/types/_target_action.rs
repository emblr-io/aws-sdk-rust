// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON format string of the Amazon Redshift Serverless API operation with input parameters. The following is an example of a target action.</p>
/// <p><code>"{"CreateSnapshot": {"NamespaceName": "sampleNamespace","SnapshotName": "sampleSnapshot", "retentionPeriod": "1"}}"</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum TargetAction {
    /// <p>The parameters that you can use to configure a <a href="https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateScheduledAction.html">scheduled action</a> to create a snapshot. For more information about creating a scheduled action, see <a href="https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateScheduledAction.html">CreateScheduledAction</a>.</p>
    CreateSnapshot(crate::types::CreateSnapshotScheduleActionParameters),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl TargetAction {
    #[allow(irrefutable_let_patterns)]
    /// Tries to convert the enum instance into [`CreateSnapshot`](crate::types::TargetAction::CreateSnapshot), extracting the inner [`CreateSnapshotScheduleActionParameters`](crate::types::CreateSnapshotScheduleActionParameters).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_create_snapshot(&self) -> ::std::result::Result<&crate::types::CreateSnapshotScheduleActionParameters, &Self> {
        if let TargetAction::CreateSnapshot(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CreateSnapshot`](crate::types::TargetAction::CreateSnapshot).
    pub fn is_create_snapshot(&self) -> bool {
        self.as_create_snapshot().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
