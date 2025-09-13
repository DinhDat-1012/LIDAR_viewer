#include "PcapLib/Lidar2DViewer.h"
#include  "main.h"
#include <vector>

int main() {
    Lidar2DViewer viewer(SCEEN_WIDTH, SCEEN_HEIGHT);  // Tạo viewer.
    std::vector<cv::Point2f> points = {cv::Point2f(100, 200), cv::Point2f(300, 400)};  // Dữ liệu LIDAR mẫu.
    viewer.update(points);  // Cập nhật điểm.
    viewer.show();          // Hiển thị.
    cv::waitKey(0);         // Chờ phím nhấn để đóng.
    return 0;
}