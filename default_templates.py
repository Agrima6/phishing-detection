"""
Default phishing simulation templates, seeded once (idempotent, by name)
into every fresh tenant database so there's a realistic library to choose
from out of the box, instead of an empty Templates page.
"""


def _render_email(accent_color: str, banner_text: str, banner_subtext: str,
                   body_paragraphs: list[str], cta_text: str, footer_text: str) -> str:
    paragraphs_html = "\n".join(
        f'              <p style="font-size:15px;color:#334155;line-height:1.6;margin:0 0 16px 0;">{p}</p>'
        for p in body_paragraphs
    )
    return f"""<html>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:Arial, Helvetica, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:24px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
          <tr>
            <td style="background-color:{accent_color};padding:28px 40px;">
              <p style="margin:0;font-size:20px;font-weight:bold;color:#ffffff;">{banner_text}</p>
              <p style="margin:4px 0 0 0;font-size:12px;color:rgba(255,255,255,0.85);">{banner_subtext}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:32px 40px;">
              <p style="font-size:15px;color:#1e293b;margin:0 0 16px 0;">{{{{greeting}}}}, {{{{first_name}}}},</p>
{paragraphs_html}
              <table cellpadding="0" cellspacing="0" style="margin:28px 0;">
                <tr>
                  <td style="background-color:{accent_color};border-radius:6px;">
                    <a href="{{{{phishing_link}}}}" target="_blank" style="display:inline-block;padding:14px 32px;font-size:15px;font-weight:bold;color:#ffffff;text-decoration:none;">
                      {cta_text}
                    </a>
                  </td>
                </tr>
              </table>
              <p style="font-size:13px;color:#64748b;line-height:1.6;margin:0;">
                {footer_text}
              </p>
            </td>
          </tr>
          <tr>
            <td style="background-color:#f8fafc;padding:20px 40px;border-top:1px solid #e2e8f0;">
              <p style="font-size:11px;color:#94a3b8;margin:0;">
                This email was sent to {{{{email}}}} as part of your organization's account security policy.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def build_default_templates(banner_image_url: str) -> list[dict]:
    """Returns the seed list. `banner_image_url` is only used by the one
    template that keeps the original uploaded shield banner image."""

    image_body = f"""<html>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:Arial, Helvetica, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:24px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
          <tr>
            <td>
              <img src="{banner_image_url}" width="600" height="140" alt="Corporate IT Security" style="display:block;width:100%;height:auto;" />
            </td>
          </tr>
          <tr>
            <td style="padding:32px 40px;">
              <p style="font-size:15px;color:#1e293b;margin:0 0 16px 0;">{{{{greeting}}}}, {{{{first_name}}}},</p>
              <p style="font-size:15px;color:#334155;line-height:1.6;margin:0 0 16px 0;">
                Our records indicate that the password for your corporate account (<strong>{{{{email}}}}</strong>) is scheduled to expire in <strong>24 hours</strong>. To avoid interruption to your email, calendar, and file access, please verify your identity and update your password before the deadline.
              </p>
              <table cellpadding="0" cellspacing="0" style="margin:28px 0;">
                <tr>
                  <td style="background-color:#d97706;border-radius:6px;">
                    <a href="{{{{phishing_link}}}}" target="_blank" style="display:inline-block;padding:14px 32px;font-size:15px;font-weight:bold;color:#ffffff;text-decoration:none;">
                      Update Password Now
                    </a>
                  </td>
                </tr>
              </table>
              <p style="font-size:13px;color:#64748b;line-height:1.6;margin:0 0 8px 0;">
                If you do not update your password within 24 hours, your account access may be temporarily suspended pending manual re-verification by the IT Helpdesk.
              </p>
              <p style="font-size:13px;color:#64748b;line-height:1.6;margin:0;">
                This is an automated message from the Corporate IT Security team. Please do not reply directly to this email.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background-color:#f8fafc;padding:20px 40px;border-top:1px solid #e2e8f0;">
              <p style="font-size:11px;color:#94a3b8;margin:0;">
                &copy; 2026 Corporate IT Security Department. This email was sent to {{{{email}}}} as part of your organization's account security policy.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    return [
        {
            "name": "IT Password Expiration Notice",
            "category": "credential-harvester",
            "subject": "Action Required: Your Password Expires in 24 Hours",
            "description": 'Simulates a corporate IT password-expiration alert to test whether employees click a suspicious "update password" link.',
            "thumbnail": banner_image_url,
            "body": image_body,
        },
        {
            "name": "Microsoft 365 Unusual Sign-in Activity",
            "category": "credential-harvester",
            "subject": "Unusual sign-in activity detected on your Microsoft account",
            "description": "Impersonates a Microsoft security alert about a sign-in from an unrecognized device, pressuring the recipient to verify their identity.",
            "thumbnail": "",
            "body": _render_email(
                "#0f6cbd", "Microsoft 365", "Account Security Alert",
                [
                    "We detected a sign-in to your account from an unrecognized device and location. If this wasn't you, your account may be compromised.",
                    "For your protection, please verify your identity immediately to secure your account and review recent activity.",
                ],
                "Verify My Account",
                "If you don't recognize this activity, review your account immediately. If you do, no further action is needed.",
            ),
        },
        {
            "name": "Shared Document via OneDrive",
            "category": "link-click",
            "subject": "\"Q4 Budget Review.xlsx\" has been shared with you",
            "description": "Mimics a routine file-share notification to test whether employees click links to open documents from unverified sources.",
            "thumbnail": "",
            "body": _render_email(
                "#094ab2", "OneDrive", "File shared with you",
                [
                    "A colleague has shared a document with you: <strong>Q4 Budget Review.xlsx</strong>.",
                    "Click below to view the file. This link will expire in 72 hours for security purposes.",
                ],
                "View Document",
                "This document was shared from within your organization's OneDrive tenant.",
            ),
        },
        {
            "name": "Payroll Direct Deposit Update Required",
            "category": "credential-harvester",
            "subject": "Action Needed: Confirm Your Direct Deposit Details",
            "description": "A finance/HR-themed lure claiming payroll details need re-verification, aiming to harvest banking credentials.",
            "thumbnail": "",
            "body": _render_email(
                "#166534", "Payroll Services", "Direct Deposit Verification",
                [
                    "Our records show your direct deposit information could not be verified for this pay cycle.",
                    "To avoid a delay in your next paycheck, please confirm your banking details before Friday's payroll run.",
                ],
                "Confirm My Details",
                "Contact HR directly if you believe this notice was sent in error.",
            ),
        },
        {
            "name": "Package Delivery Failed",
            "category": "link-click",
            "subject": "We couldn't deliver your package - action required",
            "description": "Courier-style delivery-failure notice, a very common real-world phishing lure that relies on urgency and curiosity.",
            "thumbnail": "",
            "body": _render_email(
                "#7c2d12", "Express Shipping", "Delivery Exception",
                [
                    "We attempted to deliver your package today but were unable to complete delivery due to an incomplete address.",
                    "Please confirm your delivery details within 48 hours or your package will be returned to sender.",
                ],
                "Reschedule Delivery",
                "Tracking number: EX-88213-402. This is an automated delivery notification.",
            ),
        },
        {
            "name": "Annual Benefits Enrollment Deadline",
            "category": "credential-harvester",
            "subject": "Reminder: Benefits Enrollment Closes This Friday",
            "description": "HR open-enrollment reminder used to lure employees into logging into a fake benefits portal before a fabricated deadline.",
            "thumbnail": "",
            "body": _render_email(
                "#5b21b6", "Workday", "Benefits Enrollment",
                [
                    "This is a reminder that annual benefits enrollment closes this Friday at 5:00 PM.",
                    "If you haven't reviewed your elections yet, please log in to complete your enrollment before the deadline.",
                ],
                "Review My Benefits",
                "Employees who do not complete enrollment will be defaulted to last year's elections.",
            ),
        },
        {
            "name": "VPN Client Security Update Required",
            "category": "credential-harvester",
            "subject": "Critical: VPN client update required to maintain access",
            "description": "IT-themed lure requiring re-authentication to \"update\" VPN software, targeting remote-work credentials.",
            "thumbnail": "",
            "body": _render_email(
                "#1e293b", "Corporate IT", "VPN Security Advisory",
                [
                    "A critical security update is required for your VPN client to remain compliant with company policy.",
                    "Please re-authenticate below to download and apply the update. Access may be suspended if not completed within 24 hours.",
                ],
                "Re-authenticate Now",
                "This update addresses a recently disclosed vulnerability affecting remote access clients.",
            ),
        },
        {
            "name": "Zoom Meeting Recording Shared",
            "category": "link-click",
            "subject": "Recording ready: \"Weekly Team Sync\"",
            "description": "Mimics a meeting-recording notification, a common lure exploiting the routine habit of clicking meeting links.",
            "thumbnail": "",
            "body": _render_email(
                "#2563eb", "Zoom", "Cloud Recording Available",
                [
                    "The cloud recording for <strong>\"Weekly Team Sync\"</strong> is now available.",
                    "Click below to view the recording and shared transcript.",
                ],
                "View Recording",
                "This recording will be automatically deleted after 30 days per your organization's retention policy.",
            ),
        },
        {
            "name": "HR Policy Acknowledgment Required",
            "category": "link-click",
            "subject": "Action Required: Acknowledge Updated Code of Conduct",
            "description": "Compliance-themed lure requiring employees to click through to \"acknowledge\" a policy update.",
            "thumbnail": "",
            "body": _render_email(
                "#9a3412", "Human Resources", "Policy Update",
                [
                    "Our Code of Conduct policy has been updated effective this month.",
                    "All employees are required to review and acknowledge the updated policy by end of week.",
                ],
                "Review & Acknowledge",
                "Failure to acknowledge by the deadline may be escalated to your manager.",
            ),
        },
        {
            "name": "Suspicious Login Attempt Detected",
            "category": "credential-harvester",
            "subject": "Security Alert: We stopped a suspicious login to your account",
            "description": "Generic security-alert style lure used across many real phishing kits impersonating account-protection notices.",
            "thumbnail": "",
            "body": _render_email(
                "#b91c1c", "Account Security", "Suspicious Activity Blocked",
                [
                    "We blocked a login attempt to your account from an unfamiliar location.",
                    "If this wasn't you, please secure your account immediately by verifying your identity.",
                ],
                "Secure My Account",
                "If this was you, you can safely ignore this message.",
            ),
        },
        {
            "name": "Invoice Payment Overdue",
            "category": "link-click",
            "subject": "Invoice #INV-20458 is now overdue - immediate action required",
            "description": "Accounts-payable themed lure pressuring finance staff to click through to view/pay a fabricated overdue invoice.",
            "thumbnail": "",
            "body": _render_email(
                "#0c4a6e", "Accounts Payable", "Overdue Invoice Notice",
                [
                    "Invoice <strong>#INV-20458</strong> for $4,280.00 is now 15 days overdue.",
                    "Please review and process this payment as soon as possible to avoid service interruption from this vendor.",
                ],
                "View Invoice",
                "Contact accounts payable directly with any billing questions.",
            ),
        },
    ]
