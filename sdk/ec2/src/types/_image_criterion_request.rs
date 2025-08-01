// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The list of criteria that are evaluated to determine whch AMIs are discoverable and usable in the account in the specified Amazon Web Services Region. Currently, the only criteria that can be specified are AMI providers.</p>
/// <p>Up to 10 <code>imageCriteria</code> objects can be specified, and up to a total of 200 values for all <code>imageProviders</code>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-allowed-amis.html#allowed-amis-json-configuration">JSON configuration for the Allowed AMIs criteria</a> in the <i>Amazon EC2 User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImageCriterionRequest {
    /// <p>A list of image providers whose AMIs are discoverable and useable in the account. Up to a total of 200 values can be specified.</p>
    /// <p>Possible values:</p>
    /// <p><code>amazon</code>: Allow AMIs created by Amazon Web Services.</p>
    /// <p><code>aws-marketplace</code>: Allow AMIs created by verified providers in the Amazon Web Services Marketplace.</p>
    /// <p><code>aws-backup-vault</code>: Allow AMIs created by Amazon Web Services Backup.</p>
    /// <p>12-digit account ID: Allow AMIs created by this account. One or more account IDs can be specified.</p>
    /// <p><code>none</code>: Allow AMIs created by your own account only. When <code>none</code> is specified, no other values can be specified.</p>
    pub image_providers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ImageCriterionRequest {
    /// <p>A list of image providers whose AMIs are discoverable and useable in the account. Up to a total of 200 values can be specified.</p>
    /// <p>Possible values:</p>
    /// <p><code>amazon</code>: Allow AMIs created by Amazon Web Services.</p>
    /// <p><code>aws-marketplace</code>: Allow AMIs created by verified providers in the Amazon Web Services Marketplace.</p>
    /// <p><code>aws-backup-vault</code>: Allow AMIs created by Amazon Web Services Backup.</p>
    /// <p>12-digit account ID: Allow AMIs created by this account. One or more account IDs can be specified.</p>
    /// <p><code>none</code>: Allow AMIs created by your own account only. When <code>none</code> is specified, no other values can be specified.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.image_providers.is_none()`.
    pub fn image_providers(&self) -> &[::std::string::String] {
        self.image_providers.as_deref().unwrap_or_default()
    }
}
impl ImageCriterionRequest {
    /// Creates a new builder-style object to manufacture [`ImageCriterionRequest`](crate::types::ImageCriterionRequest).
    pub fn builder() -> crate::types::builders::ImageCriterionRequestBuilder {
        crate::types::builders::ImageCriterionRequestBuilder::default()
    }
}

/// A builder for [`ImageCriterionRequest`](crate::types::ImageCriterionRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImageCriterionRequestBuilder {
    pub(crate) image_providers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ImageCriterionRequestBuilder {
    /// Appends an item to `image_providers`.
    ///
    /// To override the contents of this collection use [`set_image_providers`](Self::set_image_providers).
    ///
    /// <p>A list of image providers whose AMIs are discoverable and useable in the account. Up to a total of 200 values can be specified.</p>
    /// <p>Possible values:</p>
    /// <p><code>amazon</code>: Allow AMIs created by Amazon Web Services.</p>
    /// <p><code>aws-marketplace</code>: Allow AMIs created by verified providers in the Amazon Web Services Marketplace.</p>
    /// <p><code>aws-backup-vault</code>: Allow AMIs created by Amazon Web Services Backup.</p>
    /// <p>12-digit account ID: Allow AMIs created by this account. One or more account IDs can be specified.</p>
    /// <p><code>none</code>: Allow AMIs created by your own account only. When <code>none</code> is specified, no other values can be specified.</p>
    pub fn image_providers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.image_providers.unwrap_or_default();
        v.push(input.into());
        self.image_providers = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of image providers whose AMIs are discoverable and useable in the account. Up to a total of 200 values can be specified.</p>
    /// <p>Possible values:</p>
    /// <p><code>amazon</code>: Allow AMIs created by Amazon Web Services.</p>
    /// <p><code>aws-marketplace</code>: Allow AMIs created by verified providers in the Amazon Web Services Marketplace.</p>
    /// <p><code>aws-backup-vault</code>: Allow AMIs created by Amazon Web Services Backup.</p>
    /// <p>12-digit account ID: Allow AMIs created by this account. One or more account IDs can be specified.</p>
    /// <p><code>none</code>: Allow AMIs created by your own account only. When <code>none</code> is specified, no other values can be specified.</p>
    pub fn set_image_providers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.image_providers = input;
        self
    }
    /// <p>A list of image providers whose AMIs are discoverable and useable in the account. Up to a total of 200 values can be specified.</p>
    /// <p>Possible values:</p>
    /// <p><code>amazon</code>: Allow AMIs created by Amazon Web Services.</p>
    /// <p><code>aws-marketplace</code>: Allow AMIs created by verified providers in the Amazon Web Services Marketplace.</p>
    /// <p><code>aws-backup-vault</code>: Allow AMIs created by Amazon Web Services Backup.</p>
    /// <p>12-digit account ID: Allow AMIs created by this account. One or more account IDs can be specified.</p>
    /// <p><code>none</code>: Allow AMIs created by your own account only. When <code>none</code> is specified, no other values can be specified.</p>
    pub fn get_image_providers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.image_providers
    }
    /// Consumes the builder and constructs a [`ImageCriterionRequest`](crate::types::ImageCriterionRequest).
    pub fn build(self) -> crate::types::ImageCriterionRequest {
        crate::types::ImageCriterionRequest {
            image_providers: self.image_providers,
        }
    }
}
