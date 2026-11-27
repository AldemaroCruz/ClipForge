"""Browser actions shared by local and protected INT acceptance."""

from scripts.int_hito_a_browser import require


def submit_quick_caption_correction(page, editor, index, text, url):
    editor.locator("#clip-caption-cues textarea").nth(index).fill(text)
    save = editor.get_by_role("button", name="Guardar y exportar", exact=True)
    with page.expect_response(lambda item: item.url == url and item.request.method == "PUT") as pending:
        save.click()
    response = pending.value
    require(response.status == 202, f"quick_caption_http_{response.status}")
    return response
