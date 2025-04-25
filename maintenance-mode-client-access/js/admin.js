/**
 * Client Access Manager Admin JavaScript
 */
jQuery(document).ready(($) => {
    // Debug info
    if (typeof camAjax !== "undefined" && camAjax.debug) {
      console.log("Client Access Manager Admin JS loaded")
      console.log("Plugin URL:", camAjax.pluginUrl)
      console.log("AJAX URL:", camAjax.ajaxurl)
      console.log("Version:", camAjax.version)
    }
  
    // Media uploader for logo
    var mediaUploader
  
    $("#cam_upload_logo_button").on("click", (e) => {
      e.preventDefault()
  
      if (mediaUploader) {
        mediaUploader.open()
        return
      }
  
      mediaUploader = wp.media({
        title: "Select Company Logo",
        button: {
          text: "Use this image",
        },
        multiple: false,
      })
  
      mediaUploader.on("select", () => {
        var attachment = mediaUploader.state().get("selection").first().toJSON()
        $("#cam_logo_url").val(attachment.url)
  
        var previewContainer = $(".cam-logo-preview")
        previewContainer.html(
          '<img src="' +
            attachment.url +
            '" alt="Logo Preview" style="max-width: 50px; max-height: 50px; display: block; margin-bottom: 10px;" />',
        )
  
        if ($("#cam_remove_logo_button").length === 0) {
          $(".cam-upload-logo").after(
            '<button type="button" class="button cam-remove-logo" id="cam_remove_logo_button">Remove Logo</button>',
          )
  
          $("#cam_remove_logo_button").on("click", function (e) {
            e.preventDefault()
            $("#cam_logo_url").val("")
            $(".cam-logo-preview").html("")
            $(this).remove()
          })
        }
      })
  
      mediaUploader.open()
    })
  
    // Bind existing remove logo button if it exists
    $("#cam_remove_logo_button").on("click", function (e) {
      e.preventDefault()
      $("#cam_logo_url").val("")
      $(".cam-logo-preview").html("")
      $(this).remove()
    })
  
    // Token generation code removed - using hardcoded token instead
  })
  