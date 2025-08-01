// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the synchronization status of the Amazon Simple Storage Service (Amazon S3) account-level block public access (BPA) feature for your Lightsail buckets.</p>
/// <p>The account-level BPA feature of Amazon S3 provides centralized controls to limit public access to all Amazon S3 buckets in an account. BPA can make all Amazon S3 buckets in an Amazon Web Services account private regardless of the individual bucket and object permissions that are configured. Lightsail buckets take into account the Amazon S3 account-level BPA configuration when allowing or denying public access. To do this, Lightsail periodically fetches the account-level BPA configuration from Amazon S3. When the account-level BPA status is <code>InSync</code>, the Amazon S3 account-level BPA configuration is synchronized and it applies to your Lightsail buckets. For more information about Amazon Simple Storage Service account-level BPA and how it affects Lightsail buckets, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-block-public-access-for-buckets">Block public access for buckets in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccountLevelBpaSync {
    /// <p>The status of the account-level BPA synchronization.</p>
    /// <p>The following statuses are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>InSync</code> - Account-level BPA is synchronized. The Amazon S3 account-level BPA configuration applies to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>NeverSynced</code> - Synchronization has not yet happened. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Failed</code> - Synchronization failed. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Defaulted</code> - Synchronization failed and account-level BPA for your Lightsail buckets is defaulted to <i>active</i>.</p></li>
    /// </ul><note>
    /// <p>You might need to complete further actions if the status is <code>Failed</code> or <code>Defaulted</code>. The <code>message</code> parameter provides more information for those statuses.</p>
    /// </note>
    pub status: ::std::option::Option<crate::types::AccountLevelBpaSyncStatus>,
    /// <p>The timestamp of when the account-level BPA configuration was last synchronized. This value is null when the account-level BPA configuration has not been synchronized.</p>
    pub last_synced_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A message that provides a reason for a <code>Failed</code> or <code>Defaulted</code> synchronization status.</p>
    /// <p>The following messages are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>SYNC_ON_HOLD</code> - The synchronization has not yet happened. This status message occurs immediately after you create your first Lightsail bucket. This status message should change after the first synchronization happens, approximately 1 hour after the first bucket is created.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. The account-level BPA configuration for your Lightsail buckets is defaulted to <i>active</i> until the synchronization can occur. This means that all your buckets are private and not publicly accessible. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING_ON_HOLD</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. Account-level BPA is not yet configured for your Lightsail buckets. Therefore, only the bucket access permissions and individual object access permissions apply to your Lightsail buckets. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>Unknown</code> - The reason that synchronization failed is unknown. Contact Amazon Web ServicesSupport for more information.</p></li>
    /// </ul>
    pub message: ::std::option::Option<crate::types::BpaStatusMessage>,
    /// <p>A Boolean value that indicates whether account-level block public access is affecting your Lightsail buckets.</p>
    pub bpa_impacts_lightsail: ::std::option::Option<bool>,
}
impl AccountLevelBpaSync {
    /// <p>The status of the account-level BPA synchronization.</p>
    /// <p>The following statuses are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>InSync</code> - Account-level BPA is synchronized. The Amazon S3 account-level BPA configuration applies to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>NeverSynced</code> - Synchronization has not yet happened. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Failed</code> - Synchronization failed. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Defaulted</code> - Synchronization failed and account-level BPA for your Lightsail buckets is defaulted to <i>active</i>.</p></li>
    /// </ul><note>
    /// <p>You might need to complete further actions if the status is <code>Failed</code> or <code>Defaulted</code>. The <code>message</code> parameter provides more information for those statuses.</p>
    /// </note>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AccountLevelBpaSyncStatus> {
        self.status.as_ref()
    }
    /// <p>The timestamp of when the account-level BPA configuration was last synchronized. This value is null when the account-level BPA configuration has not been synchronized.</p>
    pub fn last_synced_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_synced_at.as_ref()
    }
    /// <p>A message that provides a reason for a <code>Failed</code> or <code>Defaulted</code> synchronization status.</p>
    /// <p>The following messages are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>SYNC_ON_HOLD</code> - The synchronization has not yet happened. This status message occurs immediately after you create your first Lightsail bucket. This status message should change after the first synchronization happens, approximately 1 hour after the first bucket is created.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. The account-level BPA configuration for your Lightsail buckets is defaulted to <i>active</i> until the synchronization can occur. This means that all your buckets are private and not publicly accessible. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING_ON_HOLD</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. Account-level BPA is not yet configured for your Lightsail buckets. Therefore, only the bucket access permissions and individual object access permissions apply to your Lightsail buckets. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>Unknown</code> - The reason that synchronization failed is unknown. Contact Amazon Web ServicesSupport for more information.</p></li>
    /// </ul>
    pub fn message(&self) -> ::std::option::Option<&crate::types::BpaStatusMessage> {
        self.message.as_ref()
    }
    /// <p>A Boolean value that indicates whether account-level block public access is affecting your Lightsail buckets.</p>
    pub fn bpa_impacts_lightsail(&self) -> ::std::option::Option<bool> {
        self.bpa_impacts_lightsail
    }
}
impl AccountLevelBpaSync {
    /// Creates a new builder-style object to manufacture [`AccountLevelBpaSync`](crate::types::AccountLevelBpaSync).
    pub fn builder() -> crate::types::builders::AccountLevelBpaSyncBuilder {
        crate::types::builders::AccountLevelBpaSyncBuilder::default()
    }
}

/// A builder for [`AccountLevelBpaSync`](crate::types::AccountLevelBpaSync).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccountLevelBpaSyncBuilder {
    pub(crate) status: ::std::option::Option<crate::types::AccountLevelBpaSyncStatus>,
    pub(crate) last_synced_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) message: ::std::option::Option<crate::types::BpaStatusMessage>,
    pub(crate) bpa_impacts_lightsail: ::std::option::Option<bool>,
}
impl AccountLevelBpaSyncBuilder {
    /// <p>The status of the account-level BPA synchronization.</p>
    /// <p>The following statuses are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>InSync</code> - Account-level BPA is synchronized. The Amazon S3 account-level BPA configuration applies to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>NeverSynced</code> - Synchronization has not yet happened. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Failed</code> - Synchronization failed. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Defaulted</code> - Synchronization failed and account-level BPA for your Lightsail buckets is defaulted to <i>active</i>.</p></li>
    /// </ul><note>
    /// <p>You might need to complete further actions if the status is <code>Failed</code> or <code>Defaulted</code>. The <code>message</code> parameter provides more information for those statuses.</p>
    /// </note>
    pub fn status(mut self, input: crate::types::AccountLevelBpaSyncStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the account-level BPA synchronization.</p>
    /// <p>The following statuses are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>InSync</code> - Account-level BPA is synchronized. The Amazon S3 account-level BPA configuration applies to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>NeverSynced</code> - Synchronization has not yet happened. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Failed</code> - Synchronization failed. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Defaulted</code> - Synchronization failed and account-level BPA for your Lightsail buckets is defaulted to <i>active</i>.</p></li>
    /// </ul><note>
    /// <p>You might need to complete further actions if the status is <code>Failed</code> or <code>Defaulted</code>. The <code>message</code> parameter provides more information for those statuses.</p>
    /// </note>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AccountLevelBpaSyncStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the account-level BPA synchronization.</p>
    /// <p>The following statuses are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>InSync</code> - Account-level BPA is synchronized. The Amazon S3 account-level BPA configuration applies to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>NeverSynced</code> - Synchronization has not yet happened. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Failed</code> - Synchronization failed. The Amazon S3 account-level BPA configuration does not apply to your Lightsail buckets.</p></li>
    /// <li>
    /// <p><code>Defaulted</code> - Synchronization failed and account-level BPA for your Lightsail buckets is defaulted to <i>active</i>.</p></li>
    /// </ul><note>
    /// <p>You might need to complete further actions if the status is <code>Failed</code> or <code>Defaulted</code>. The <code>message</code> parameter provides more information for those statuses.</p>
    /// </note>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AccountLevelBpaSyncStatus> {
        &self.status
    }
    /// <p>The timestamp of when the account-level BPA configuration was last synchronized. This value is null when the account-level BPA configuration has not been synchronized.</p>
    pub fn last_synced_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_synced_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the account-level BPA configuration was last synchronized. This value is null when the account-level BPA configuration has not been synchronized.</p>
    pub fn set_last_synced_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_synced_at = input;
        self
    }
    /// <p>The timestamp of when the account-level BPA configuration was last synchronized. This value is null when the account-level BPA configuration has not been synchronized.</p>
    pub fn get_last_synced_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_synced_at
    }
    /// <p>A message that provides a reason for a <code>Failed</code> or <code>Defaulted</code> synchronization status.</p>
    /// <p>The following messages are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>SYNC_ON_HOLD</code> - The synchronization has not yet happened. This status message occurs immediately after you create your first Lightsail bucket. This status message should change after the first synchronization happens, approximately 1 hour after the first bucket is created.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. The account-level BPA configuration for your Lightsail buckets is defaulted to <i>active</i> until the synchronization can occur. This means that all your buckets are private and not publicly accessible. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING_ON_HOLD</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. Account-level BPA is not yet configured for your Lightsail buckets. Therefore, only the bucket access permissions and individual object access permissions apply to your Lightsail buckets. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>Unknown</code> - The reason that synchronization failed is unknown. Contact Amazon Web ServicesSupport for more information.</p></li>
    /// </ul>
    pub fn message(mut self, input: crate::types::BpaStatusMessage) -> Self {
        self.message = ::std::option::Option::Some(input);
        self
    }
    /// <p>A message that provides a reason for a <code>Failed</code> or <code>Defaulted</code> synchronization status.</p>
    /// <p>The following messages are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>SYNC_ON_HOLD</code> - The synchronization has not yet happened. This status message occurs immediately after you create your first Lightsail bucket. This status message should change after the first synchronization happens, approximately 1 hour after the first bucket is created.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. The account-level BPA configuration for your Lightsail buckets is defaulted to <i>active</i> until the synchronization can occur. This means that all your buckets are private and not publicly accessible. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING_ON_HOLD</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. Account-level BPA is not yet configured for your Lightsail buckets. Therefore, only the bucket access permissions and individual object access permissions apply to your Lightsail buckets. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>Unknown</code> - The reason that synchronization failed is unknown. Contact Amazon Web ServicesSupport for more information.</p></li>
    /// </ul>
    pub fn set_message(mut self, input: ::std::option::Option<crate::types::BpaStatusMessage>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message that provides a reason for a <code>Failed</code> or <code>Defaulted</code> synchronization status.</p>
    /// <p>The following messages are possible:</p>
    /// <ul>
    /// <li>
    /// <p><code>SYNC_ON_HOLD</code> - The synchronization has not yet happened. This status message occurs immediately after you create your first Lightsail bucket. This status message should change after the first synchronization happens, approximately 1 hour after the first bucket is created.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. The account-level BPA configuration for your Lightsail buckets is defaulted to <i>active</i> until the synchronization can occur. This means that all your buckets are private and not publicly accessible. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>DEFAULTED_FOR_SLR_MISSING_ON_HOLD</code> - The synchronization failed because the required service-linked role is missing from your Amazon Web Services account. Account-level BPA is not yet configured for your Lightsail buckets. Therefore, only the bucket access permissions and individual object access permissions apply to your Lightsail buckets. For more information about how to create the required service-linked role to allow synchronization, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-using-service-linked-roles">Using Service-Linked Roles for Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>Unknown</code> - The reason that synchronization failed is unknown. Contact Amazon Web ServicesSupport for more information.</p></li>
    /// </ul>
    pub fn get_message(&self) -> &::std::option::Option<crate::types::BpaStatusMessage> {
        &self.message
    }
    /// <p>A Boolean value that indicates whether account-level block public access is affecting your Lightsail buckets.</p>
    pub fn bpa_impacts_lightsail(mut self, input: bool) -> Self {
        self.bpa_impacts_lightsail = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value that indicates whether account-level block public access is affecting your Lightsail buckets.</p>
    pub fn set_bpa_impacts_lightsail(mut self, input: ::std::option::Option<bool>) -> Self {
        self.bpa_impacts_lightsail = input;
        self
    }
    /// <p>A Boolean value that indicates whether account-level block public access is affecting your Lightsail buckets.</p>
    pub fn get_bpa_impacts_lightsail(&self) -> &::std::option::Option<bool> {
        &self.bpa_impacts_lightsail
    }
    /// Consumes the builder and constructs a [`AccountLevelBpaSync`](crate::types::AccountLevelBpaSync).
    pub fn build(self) -> crate::types::AccountLevelBpaSync {
        crate::types::AccountLevelBpaSync {
            status: self.status,
            last_synced_at: self.last_synced_at,
            message: self.message,
            bpa_impacts_lightsail: self.bpa_impacts_lightsail,
        }
    }
}
